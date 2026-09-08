"""
Enotni testi za FastAPI strežnik in REST končne točke.
"""

from fastapi.testclient import TestClient
from app.server import app


client = TestClient(app)


def test_index_page():
    resp = client.get("/")
    assert resp.status_code == 200
    assert "SAFEER CONTROL" in resp.text
    assert "TV Daljinec" in resp.text


def test_get_devices():
    resp = client.get("/api/devices")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    device_ids = [d["id"] for d in data]
    assert "living_room_tv" in device_ids
    assert "living_room_audio" in device_ids


def test_api_action_policy_blocked():
    payload = {
        "device_id": "living_room_tv",
        "action": "raw_shell_command",
        "params": {"cmd": "id"}
    }
    resp = client.post("/api/action", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is False
    assert "VARNOSTNA BLOKADA" in data["message"]


def test_get_scenes():
    resp = client.get("/api/scenes")
    assert resp.status_code == 200
    data = resp.json()
    scene_ids = [s["id"] for s in data]
    assert "cinema" in scene_ids
    assert "music" in scene_ids
    assert "power_off" in scene_ids
