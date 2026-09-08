"""
FastAPI strežnik za Safeer Control.
Omogoča REST API in spletni/mobilni vmesnik za upravljanje naprav.
"""

import os
import asyncio
from pathlib import Path
from typing import List, Dict, Any
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from safeer_control.core.config import get_settings
from safeer_control.core.models import ActionRequest, ActionResult, Device, Scene
from safeer_control.core.registry import get_registry
from safeer_control.core.action_engine import get_action_engine
from safeer_control.core.scene_engine import get_scene_engine

# Poti do spletnih statičnih datotek
WEB_DIR = Path(__file__).resolve().parent.parent / "web"

app = FastAPI(
    title="Safeer Control API",
    description="Varno lokalno vozlišče za upravljanje pametnih naprav in Safeer ekosistema",
    version="0.1.0"
)

# CORS dovoljenja za lokalni dostop
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/devices", response_model=List[Device])
def list_devices():
    """Vrne seznam vseh registriranih naprav z osveženim stanjem."""
    registry = get_registry()
    registry.refresh_all()
    return registry.list_devices()


@app.post("/api/action", response_model=ActionResult)
def execute_action(request: ActionRequest):
    """Izvede varno dejanje na določeni napravi prek PolicyEngine."""
    engine = get_action_engine()
    result = engine.dispatch(request)
    return result


@app.get("/api/scenes", response_model=List[Scene])
def list_scenes():
    """Vrne seznam vseh razpoložljivih scen."""
    scene_engine = get_scene_engine()
    return scene_engine.list_scenes()


@app.post("/api/scenes/{scene_id}/execute", response_model=List[ActionResult])
def execute_scene(scene_id: str):
    """Izvede vse korake izbrane scene."""
    scene_engine = get_scene_engine()
    results = scene_engine.execute_scene(scene_id)
    if not results:
        raise HTTPException(status_code=404, detail=f"Scena '{scene_id}' ni najdena.")
    return results


@app.get("/api/tv/screenshot")
def get_tv_screenshot():
    """Zajame in vrne živo sliko zaslona televizorja v formatu PNG."""
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


@app.websocket("/ws")
async def websocket_status_feed(websocket: WebSocket):
    """WebSocket kanal za živo posodabljanje stanja naprav."""
    await websocket.accept()
    registry = get_registry()
    try:
        while True:
            # Osveži stanje vseh naprav in pošlji odjemalcu vsake 3 sekunde
            devices = registry.list_devices()
            data = [d.model_dump() for d in devices]
            await websocket.send_json({"type": "devices_update", "data": data})
            await asyncio.sleep(3.0)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass


# Streženje spletnega vmesnika (UI)
if WEB_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")

    @app.get("/")
    def serve_index():
        return FileResponse(str(WEB_DIR / "index.html"))


def start_server(host: str = "0.0.0.0", port: int = 8989):
    """Zagon Uvicorn strežnika."""
    settings = get_settings()
    actual_host = host or settings.server_host
    actual_port = port or settings.server_port
    print(f"🚀 Safeer Control teče na http://{actual_host}:{actual_port}")
    uvicorn.run(app, host=actual_host, port=actual_port, log_level="info")


if __name__ == "__main__":
    start_server()
