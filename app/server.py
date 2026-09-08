"""
FastAPI strežnik za Safeer Control (V0.2 — Security Foundation).
Zaščiten API (obvezna avtentikacija z žetonom, strikten CORS za LAN, revizijski dnevnik).
"""

import os
import hmac
import asyncio
from pathlib import Path
from typing import List, Optional
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Request, Depends, Security, Header, Query, status
from fastapi.responses import FileResponse, Response, JSONResponse
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
from scenes.models import Scene
from scenes.engine import get_scene_engine

STATIC_DIR = Path(__file__).resolve().parent / "static"

app = FastAPI(
    title="Safeer Control API",
    description="Varno lokalno vozlišče za upravljanje pametnih naprav in Safeer ekosistema",
    version="0.2.0"
)

# 1. Odprava CORS * — dovoljeni le eksplicitni lokalni izvori
settings = get_settings()
ALLOWED_ORIGIN_REGEX = r"^http://(localhost|127\.0\.0\.1|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+)(:\d+)?$"

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=ALLOWED_ORIGIN_REGEX,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-Safeer-Token", "Authorization"],
)

# 2. Avtentikacijski mehanizem (X-Safeer-Token ali ?token=)
api_key_header = APIKeyHeader(name="X-Safeer-Token", auto_error=False)


def verify_token(
    x_safeer_token: Optional[str] = Security(api_key_header),
    token: Optional[str] = Query(None, alias="token")
) -> str:
    provided = x_safeer_token or token
    expected = get_settings().auth_token
    if not provided or not hmac.compare_digest(provided, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Neveljaven ali manjkajoč Safeer avtentikacijski žeton (X-Safeer-Token)."
        )
    return provided


@app.post("/api/auth/verify")
def verify_auth(
    x_safeer_token: Optional[str] = Header(None, alias="X-Safeer-Token"),
    token: Optional[str] = Query(None)
):
    provided = x_safeer_token or token
    expected = get_settings().auth_token
    if provided and hmac.compare_digest(provided, expected):
        return {"valid": True, "message": "Avtentikacija uspešna"}
    raise HTTPException(status_code=401, detail="Neveljaven žeton.")


@app.get("/api/devices", response_model=List[Device], dependencies=[Depends(verify_token)])
def list_devices():
    registry = get_registry()
    registry.refresh_all()
    return registry.list_devices()


@app.post("/api/action", response_model=ActionResult, dependencies=[Depends(verify_token)])
def execute_action(action_req: ActionRequest, request: Request):
    client_ip = request.client.host if request.client else "127.0.0.1"
    engine = get_action_engine()
    result = engine.dispatch(action_req, actor_ip=client_ip, actor_type="web_ui")
    return result


@app.get("/api/scenes", response_model=List[Scene], dependencies=[Depends(verify_token)])
def list_scenes():
    scene_engine = get_scene_engine()
    return scene_engine.list_scenes()


@app.post("/api/scenes/{scene_id}/execute", response_model=List[ActionResult], dependencies=[Depends(verify_token)])
def execute_scene(scene_id: str, request: Request):
    client_ip = request.client.host if request.client else "127.0.0.1"
    scene_engine = get_scene_engine()
    results = scene_engine.execute_scene(scene_id)
    if not results:
        raise HTTPException(status_code=404, detail=f"Scena '{scene_id}' ni najdena.")
    return results


@app.get("/api/tv/screenshot", dependencies=[Depends(verify_token)])
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


@app.get("/api/audit/logs", dependencies=[Depends(verify_token)])
def get_audit_logs(limit: int = 50):
    logger = get_audit_logger()
    return logger.get_recent(limit=limit)


@app.websocket("/ws")
async def websocket_status_feed(websocket: WebSocket, token: Optional[str] = Query(None)):
    expected = get_settings().auth_token
    if not token or not hmac.compare_digest(token, expected):
        await websocket.close(code=1008)
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


def start_server(host: str = "0.0.0.0", port: int = 8990):
    cfg = get_settings()
    actual_host = host or cfg.server_host
    actual_port = port or cfg.server_port
    print(f"🚀 Safeer Control V0.2 teče na http://{actual_host}:{actual_port}")
    print(f"🔑 Auth Token: {cfg.auth_token}")
    print(f"📱 Web URL: http://{actual_host}:{actual_port}/?token={cfg.auth_token}")
    uvicorn.run(app, host=actual_host, port=actual_port, log_level="info")


if __name__ == "__main__":
    start_server()
