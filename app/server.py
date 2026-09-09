"""
FastAPI strežnik za Safeer Control (V0.2.1 — Security Hardening).
Zaščiten API: kratkotrajne seje (Short-Lived Sessions), enokratne WebSocket vstopnice (Single-Use Tickets),
striktna prepoved tokenov v URL/konzoli in varno LAN komuniciranje.
"""

import os
import hmac
import asyncio
from pathlib import Path
from typing import List, Optional
from pydantic import BaseModel
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Request, Depends, Security, Header, Query, status
from fastapi.responses import FileResponse, Response, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
import uvicorn

from core.config import get_settings
from core.devices.models import Device
from core.devices.registry import get_registry
from core.actions.models import ActionRequest, ActionResult
from core.actions.engine import get_action_engine
from core.security.audit import get_audit_logger
from core.security.session import get_session_manager
from scenes.models import Scene, SceneExecutionReport
from scenes.engine import get_scene_engine

STATIC_DIR = Path(__file__).resolve().parent / "static"

app = FastAPI(
    title="Safeer Control API",
    description="Varno lokalno vozlišče za upravljanje pametnih naprav in Safeer ekosistema",
    version="0.3.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# 1. Odprava CORS * — dovoljeni le eksplicitni lokalni izvori
ALLOWED_ORIGIN_REGEX = r"^(http://(localhost|127\.0\.0\.1|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+)(:\d+)?|https://([a-zA-Z0-9-]+\.)*safeer\.si|https://([a-zA-Z0-9-]+\.)*trycloudflare\.com)$"

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=ALLOWED_ORIGIN_REGEX,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-Safeer-Token", "X-Safeer-Session", "Authorization"],
)

# 2. Avtentikacijski mehanizem prek Headers (BREZ query parametrov v URL-jih!)
api_key_header = APIKeyHeader(name="X-Safeer-Token", auto_error=False)
session_header = APIKeyHeader(name="X-Safeer-Session", auto_error=False)


def verify_authenticated_caller(
    x_safeer_token: Optional[str] = Security(api_key_header),
    x_safeer_session: Optional[str] = Security(session_header),
    authorization: Optional[str] = Header(None)
) -> str:
    sm = get_session_manager()
    cfg = get_settings()

    # 1. Preveri sejo (X-Safeer-Session)
    if x_safeer_session and sm.validate_session(x_safeer_session):
        return x_safeer_session

    # 2. Preveri Authorization Bearer header (seja ali žeton)
    if authorization and authorization.lower().startswith("bearer "):
        bearer_val = authorization[7:].strip()
        if sm.validate_session(bearer_val):
            return bearer_val
        if hmac.compare_digest(bearer_val, cfg.auth_token):
            return bearer_val

    # 3. Preveri neposredni X-Safeer-Token
    if x_safeer_token and hmac.compare_digest(x_safeer_token, cfg.auth_token):
        return x_safeer_token

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Neveljaven ali manjkajoč avtentikacijski credential (uporabite sejo ali Authorization header)."
    )


class SessionExchangeRequest(BaseModel):
    token: str


@app.post("/api/auth/session")
def create_session(req: SessionExchangeRequest, request: Request):
    """
    Zamenja dolgoročni Safeer Auth Token za kratkotrajno sejo (24 ur).
    Tako glavni žeton ne kroži pri vsakem klicu.
    """
    cfg = get_settings()
    if not req.token or not hmac.compare_digest(req.token.strip(), cfg.auth_token):
        raise HTTPException(status_code=401, detail="Neveljaven Safeer Auth Token.")

    client_ip = request.client.host if request.client else "127.0.0.1"
    sm = get_session_manager()
    session_id = sm.create_session(client_ip=client_ip)
    return {
        "authenticated": True,
        "session_token": session_id,
        "expires_in_seconds": sm.default_session_ttl
    }


@app.post("/api/auth/ws-ticket", dependencies=[Depends(verify_authenticated_caller)])
def create_ws_ticket():
    """
    Ustvari varno enokratno vstopnico (Single-Use Ticket) z veljavnostjo 30 sekund za WebSocket.
    """
    sm = get_session_manager()
    ticket = sm.create_ws_ticket()
    return {"ticket": ticket, "expires_in_seconds": sm.ticket_ttl}


@app.post("/api/auth/verify")
def verify_auth(
    x_safeer_token: Optional[str] = Header(None, alias="X-Safeer-Token"),
    x_safeer_session: Optional[str] = Header(None, alias="X-Safeer-Session"),
    authorization: Optional[str] = Header(None)
):
    try:
        verify_authenticated_caller(
            x_safeer_token=x_safeer_token,
            x_safeer_session=x_safeer_session,
            authorization=authorization
        )
        return {"valid": True, "message": "Avtentikacija uspešna"}
    except HTTPException:
        raise HTTPException(status_code=401, detail="Neveljaven žeton ali potekla seja.")


@app.get("/api/devices", response_model=List[Device], dependencies=[Depends(verify_authenticated_caller)])
def list_devices():
    registry = get_registry()
    registry.refresh_all()
    return registry.list_devices()


class PinPairRequest(BaseModel):
    pin: str


class CompanionUpdateApiRequest(BaseModel):
    binary_b64: str
    sha256: str
    release_signature: str
    version: Optional[str] = None
    restart: bool = True



@app.get("/api/devices/{device_id}/pairing", dependencies=[Depends(verify_authenticated_caller)])
def get_device_pairing_status(device_id: str):
    from core.security.keystore import get_keystore
    registry = get_registry()
    device = registry.get_device(device_id)
    if not device:
        raise HTTPException(status_code=404, detail=f"Naprava '{device_id}' ni registrirana.")

    keystore = get_keystore()
    key = keystore.get_key(device_id)
    tls_fp = keystore.get_tls_fingerprint(device_id)
    provider = registry.get_provider(device_id)
    if not key and provider and hasattr(provider, "keystore") and provider.keystore:
        key = provider.keystore.get_key(device_id)
    if not key and provider and hasattr(provider, "transport") and getattr(provider.transport, "secret_token", None):
        key = provider.transport.secret_token
    is_paired = key is not None

    health_info = None
    if provider and hasattr(provider, "transport") and hasattr(provider.transport, "check_health"):
        try:
            is_healthy = provider.transport.check_health()
            health_info = {"healthy": is_healthy}
        except Exception:
            health_info = {"healthy": False}

    # Enosmerni SHA-256 prstni odtis — NIKOLI ne razkrivamo delov dejanskega ključa!
    fingerprint = keystore.compute_fingerprint(key) if key else None

    return {
        "device_id": device_id,
        "is_paired": is_paired,
        "fingerprint": fingerprint,
        "tls_fingerprint": tls_fp,
        "tls_enabled": getattr(getattr(provider, "transport", None), "use_tls", bool(tls_fp)),
        "health": health_info
    }


@app.post("/api/devices/{device_id}/pair-pin", dependencies=[Depends(verify_authenticated_caller)])
def pair_device_pin_endpoint(device_id: str, req: PinPairRequest, response: Response):
    """
    V0.8 Interaktivna seznanitev s 6-mestnim PIN-om prek TLS šifrirane povezave.
    Izvede PIN handshake, izpelje 256-bitni ključ prek HKDF-SHA256,
    pripne certifikatni SHA-256 prstni odtis in shrani v KeyStore.
    Surovega skrivnega ključa NE razkriva v odzivu (Zero Exposure).
    """
    from core.security.keystore import get_keystore
    registry = get_registry()
    device = registry.get_device(device_id)
    if not device:
        raise HTTPException(status_code=404, detail=f"Naprava '{device_id}' ni registrirana.")

    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response.headers["Pragma"] = "no-cache"

    provider = registry.get_provider(device_id)
    if not provider or not hasattr(provider, "pair_pin"):
        raise HTTPException(status_code=400, detail="Ponudnik naprave ne podpira PIN seznanitve.")

    try:
        derived_key, tls_fp = provider.pair_pin(req.pin)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Seznanitev ni uspela: {e}")

    keystore = get_keystore()
    key_fp = keystore.compute_fingerprint(derived_key)

    return {
        "device_id": device_id,
        "paired": True,
        "tls_pinned": True,
        "tls_fingerprint": tls_fp,
        "key_fingerprint": key_fp,
        "message": "Naprava uspešno seznanjena prek TLS s preverjanjem prstnega odtisa."
    }


@app.post("/api/devices/{device_id}/pair", dependencies=[Depends(verify_authenticated_caller)])
def pair_device_endpoint(device_id: str, response: Response):
    """
    Eksplicitna enkratna seznanitev naprave.
    Vrne nov 256-bitni ključ z no-store predpomnjenjem, varno shranjen v KeyStore (0600).
    """
    from core.security.keystore import get_keystore
    registry = get_registry()
    device = registry.get_device(device_id)
    if not device:
        raise HTTPException(status_code=404, detail=f"Naprava '{device_id}' ni registrirana.")

    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response.headers["Pragma"] = "no-cache"

    provider = registry.get_provider(device_id)
    if provider and hasattr(provider, "pair"):
        new_key = provider.pair()
    else:
        keystore = get_keystore()
        new_key = keystore.get_or_create_key(device_id)

    fingerprint = get_keystore().compute_fingerprint(new_key)

    return {
        "device_id": device_id,
        "paired": True,
        "secret_key": new_key,
        "fingerprint": fingerprint,
        "instructions": (
            "256-bitni ključ je prikazan le enkrat ob seznanitvi. "
            "Varno ga shranite na ciljno napravo z datotečnimi pravicami 0600."
        )
    }


@app.post("/api/devices/{device_id}/rotate-key", dependencies=[Depends(verify_authenticated_caller)])
def rotate_device_key_endpoint(device_id: str, response: Response):
    """Rotira 256-bitni ključ naprave v KeyStore z no-store predpomnjenjem."""
    from core.security.keystore import get_keystore
    registry = get_registry()
    device = registry.get_device(device_id)
    if not device:
        raise HTTPException(status_code=404, detail=f"Naprava '{device_id}' ni registrirana.")

    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response.headers["Pragma"] = "no-cache"

    provider = registry.get_provider(device_id)
    if provider and hasattr(provider, "rotate_secret"):
        new_key = provider.rotate_secret()
    else:
        keystore = get_keystore()
        new_key = keystore.rotate_key(device_id)

    fingerprint = get_keystore().compute_fingerprint(new_key)

    return {
        "device_id": device_id,
        "rotated": True,
        "secret_key": new_key,
        "fingerprint": fingerprint
    }


@app.post("/api/devices/{device_id}/revoke-key", dependencies=[Depends(verify_authenticated_caller)])
def revoke_device_key_endpoint(device_id: str):
    """Prekliče ključ naprave v KeyStore in odstrani ključ iz transporta."""
    from core.security.keystore import get_keystore
    registry = get_registry()
    device = registry.get_device(device_id)
    if not device:
        raise HTTPException(status_code=404, detail=f"Naprava '{device_id}' ni registrirana.")

    keystore = get_keystore()
    revoked = keystore.revoke_key(device_id)

    provider = registry.get_provider(device_id)
    if provider and hasattr(provider, "transport") and hasattr(provider.transport, "secret_token"):
        provider.transport.secret_token = None

    return {
        "device_id": device_id,
        "revoked": revoked
    }


@app.get("/api/devices/{device_id}/companion/lifecycle", dependencies=[Depends(verify_authenticated_caller)])
def get_companion_lifecycle_endpoint(device_id: str):
    """Vrne podrobno poročilo o življenjskem ciklu Companion storitve."""
    registry = get_registry()
    device = registry.get_device(device_id)
    if not device:
        raise HTTPException(status_code=404, detail=f"Naprava '{device_id}' ni registrirana.")

    provider = registry.get_provider(device_id)
    if not provider or not hasattr(provider, "get_lifecycle_status"):
        raise HTTPException(status_code=400, detail="Ponudnik naprave ne podpira pregleda življenjskega cikla.")

    return provider.get_lifecycle_status()


@app.post("/api/devices/{device_id}/companion/update", dependencies=[Depends(verify_authenticated_caller)])
def update_companion_endpoint(device_id: str, req: CompanionUpdateApiRequest, response: Response):
    """Izvede nadzorovano posodobitev (OTA) Companion programa s preverjanjem SHA-256."""
    import base64
    registry = get_registry()
    device = registry.get_device(device_id)
    if not device:
        raise HTTPException(status_code=404, detail=f"Naprava '{device_id}' ni registrirana.")

    provider = registry.get_provider(device_id)
    if not provider or not hasattr(provider, "update_companion"):
        raise HTTPException(status_code=400, detail="Ponudnik naprave ne podpira nadzorovanih posodobitev.")

    try:
        bin_bytes = base64.b64decode(req.binary_b64)
    except Exception:
        raise HTTPException(status_code=400, detail="Neveljaven base64 binarni tovor.")

    actual_sha = hashlib.sha256(bin_bytes).hexdigest().lower()
    if actual_sha != req.sha256.strip().lower():
        raise HTTPException(
            status_code=400,
            detail=f"Fail-closed: SHA-256 hash mismatch! Pričakovano: {req.sha256}, dobljeno: {actual_sha}"
        )

    res = provider.update_companion(
        binary_bytes=bin_bytes,
        release_signature=req.release_signature,
        version=req.version,
        restart=req.restart
    )
    if not res.get("success"):
        raise HTTPException(status_code=500, detail=res.get("error_message", "Posodobitev ni uspela"))
    return res


@app.post("/api/action", response_model=ActionResult, dependencies=[Depends(verify_authenticated_caller)])
def execute_action(action_req: ActionRequest, request: Request):
    client_ip = request.client.host if request.client else "127.0.0.1"
    engine = get_action_engine()
    result = engine.dispatch(action_req, actor_ip=client_ip, actor_type="web_ui")
    return result


@app.get("/api/scenes", response_model=List[Scene], dependencies=[Depends(verify_authenticated_caller)])
def list_scenes():
    scene_engine = get_scene_engine()
    return scene_engine.list_scenes()


@app.post("/api/scenes/{scene_id}/execute", response_model=SceneExecutionReport, dependencies=[Depends(verify_authenticated_caller)])
def execute_scene(scene_id: str, request: Request, url: Optional[str] = Query(None)):
    client_ip = request.client.host if request.client else "127.0.0.1"
    scene_engine = get_scene_engine()
    if not scene_engine.get_scene(scene_id):
        raise HTTPException(status_code=404, detail=f"Scena '{scene_id}' ni najdena.")
    report = scene_engine.execute_scene(scene_id, actor_ip=client_ip, actor_type="web_ui", optional_url=url)
    return report


@app.get("/api/tv/screenshot", dependencies=[Depends(verify_authenticated_caller)])
def get_tv_screenshot():
    registry = get_registry()
    provider = registry.get_provider("living_room_tv")
    if not provider:
        raise HTTPException(status_code=404, detail="TV ponudnik ni registriran.")

    import subprocess
    try:
        cmd = ["adb", "-s", f"{provider.device.host}:{provider.device.port}", "exec-out", "screencap", "-p"]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=4.0)
        if res.returncode == 0 and len(res.stdout) > 1000:
            return Response(content=res.stdout, media_type="image/png")
        raise HTTPException(status_code=503, detail="Zajem slike ni uspel (morda je TV ugasnjen).")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/audit/logs", dependencies=[Depends(verify_authenticated_caller)])
def get_audit_logs(limit: int = 50):
    logger = get_audit_logger()
    return logger.get_recent(limit=limit)


@app.websocket("/ws")
async def websocket_status_feed(websocket: WebSocket, ticket: Optional[str] = Query(None)):
    """
    WebSocket z enokratno vstopnico (Single-Use Ticket) ali veljavno sejo.
    Vstopnica se takoj pokuri in postane neveljavna za vse nadaljnje povezave.
    """
    sm = get_session_manager()
    if not ticket or not sm.consume_ws_ticket(ticket):
        await websocket.close(code=1008, reason="Invalid or expired ticket")
        return

    await websocket.accept()
    registry = get_registry()
    try:
        while True:
            devices = registry.list_devices()
            data = [d.model_dump() for d in devices]
            await websocket.send_json({"type": "devices_update", "data": data})
            await asyncio.sleep(3.0)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass


if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.get("/")
    def serve_index():
        return FileResponse(str(STATIC_DIR / "index.html"))

    @app.get("/portal")
    @app.get("/landing")
    @app.get("/control")
    def serve_landing():
        landing_file = STATIC_DIR / "landing.html"
        if landing_file.exists():
            return FileResponse(str(landing_file))
        return FileResponse(str(STATIC_DIR / "index.html"))

    @app.get("/browser")
    def serve_browser():
        return RedirectResponse(url="https://memelandfaner.github.io/-safeer-browser/", status_code=302)

    @app.get("/download")
    def serve_download_redirect():
        return RedirectResponse(url="/control#install", status_code=302)

    @app.get("/security")
    def serve_security_redirect():
        return RedirectResponse(url="/control#security", status_code=302)

    @app.get("/docs")
    def serve_docs_redirect():
        return RedirectResponse(url="/control#faq", status_code=302)

    @app.get("/ecosystem")
    def serve_ecosystem_redirect():
        return RedirectResponse(url="/control#ecosystem", status_code=302)

    @app.get("/install.sh")
    def serve_installer():
        script_file = Path(__file__).resolve().parent.parent / "scripts" / "install.sh"
        if script_file.exists():
            return FileResponse(str(script_file), media_type="text/x-shellscript")
        raise HTTPException(status_code=404, detail="Installer script not found.")

    DOWNLOADS_DIR = STATIC_DIR / "downloads"
    if DOWNLOADS_DIR.exists():
        app.mount("/downloads", StaticFiles(directory=str(DOWNLOADS_DIR)), name="downloads")

    ASSETS_DIR = STATIC_DIR / "assets"
    if ASSETS_DIR.exists():
        app.mount("/assets", StaticFiles(directory=str(ASSETS_DIR)), name="assets")

    CSS_DIR = STATIC_DIR / "css"
    if CSS_DIR.exists():
        app.mount("/css", StaticFiles(directory=str(CSS_DIR)), name="css")

    @app.get("/download/apk")
    def download_apk():
        apk_path = STATIC_DIR / "downloads" / "SafeerCompanion.apk"
        if apk_path.exists():
            return FileResponse(str(apk_path), media_type="application/vnd.android.package-archive", filename="SafeerCompanion.apk")
        raise HTTPException(status_code=404, detail="APK datoteka ni najdena.")

    @app.get("/download/tv-binary")
    def download_tv_binary():
        bin_path = STATIC_DIR / "downloads" / "safeer-companion-android-arm64"
        if bin_path.exists():
            return FileResponse(str(bin_path), media_type="application/octet-stream", filename="safeer-companion-android-arm64")
        raise HTTPException(status_code=404, detail="TV binarna datoteka ni najdena.")


def start_server(host: str = "0.0.0.0", port: int = 8990):
    cfg = get_settings()
    actual_host = host or cfg.server_host
    actual_port = port or cfg.server_port
    print(f"🚀 Safeer Control V0.3 teče na http://{actual_host}:{actual_port}")
    print(f"🔒 Avtentikacija: Aktivna (Skrivnosti niso izpisane v konzoli ali URL-jih)")
    uvicorn.run(app, host=actual_host, port=actual_port, log_level="info")


if __name__ == "__main__":
    start_server()
