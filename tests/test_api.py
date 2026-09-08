"""
Enotni testi za FastAPI strežnik, REST končne točke in API avtentikacijo.
"""

from fastapi.testclient import TestClient
from app.server import app
from core.config import get_settings

client = TestClient(app)
settings = get_settings()
AUTH_HEADERS = {"X-Safeer-Token": settings.auth_token}


def test_index_page():
    resp = client.get("/")
    assert resp.status_code == 200
    assert "SAFEER CONTROL" in resp.text
    assert "TV Daljinec" in resp.text


def test_unauthenticated_api_rejected():
    resp = client.get("/api/devices")
    assert resp.status_code == 401
    assert "Neveljaven ali manjkajoč" in resp.text

    resp_action = client.post("/api/action", json={"device_id": "living_room_tv", "action": "status"})
    assert resp_action.status_code == 401


def test_invalid_token_rejected():
    resp = client.get("/api/devices", headers={"X-Safeer-Token": "bad-token-xyz"})
    assert resp.status_code == 401


def test_authenticated_get_devices():
    resp = client.get("/api/devices", headers=AUTH_HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    device_ids = [d["id"] for d in data]
    assert "living_room_tv" in device_ids
    assert "living_room_audio" in device_ids


def test_auth_verify_endpoint():
    # Neveljaven žeton
    resp_bad = client.post("/api/auth/verify", headers={"X-Safeer-Token": "wrong"})
    assert resp_bad.status_code == 401

    # Veljaven žeton
    resp_ok = client.post("/api/auth/verify", headers=AUTH_HEADERS)
    assert resp_ok.status_code == 200
    assert resp_ok.json()["valid"] is True


def test_api_action_policy_blocked():
    payload = {
        "device_id": "living_room_tv",
        "action": "raw_shell_command",
        "params": {"cmd": "id"}
    }
    resp = client.post("/api/action", json=payload, headers=AUTH_HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is False
    assert "VARNOSTNA BLOKADA" in data["message"]


def test_get_scenes_authenticated():
    resp = client.get("/api/scenes", headers=AUTH_HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    scene_ids = [s["id"] for s in data]
    assert "cinema" in scene_ids
    assert "music" in scene_ids
    assert "power_off" in scene_ids


def test_audit_logs_endpoint():
    resp = client.get("/api/audit/logs", headers=AUTH_HEADERS)
    assert resp.status_code == 200
    logs = resp.json()
    assert isinstance(logs, list)
