"""
Enotni testi za FastAPI strežnik, REST končne točke, kratkotrajne seje in API avtentikacijo (V0.2.1).
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


def test_reject_token_in_url_query():
    # V0.2.1: Žeton v query stringu je izrecno prepovedan in zavrnjen!
    resp = client.get(f"/api/devices?token={settings.auth_token}")
    assert resp.status_code == 401


def test_invalid_token_rejected():
    resp = client.get("/api/devices", headers={"X-Safeer-Token": "bad-token-xyz"})
    assert resp.status_code == 401


def test_session_exchange_and_authenticated_calls():
    # 1. Napačen žeton za sejo
    bad_sess = client.post("/api/auth/session", json={"token": "wrong-secret"})
    assert bad_sess.status_code == 401

    # 2. Veljaven žeton izda kratkotrajno sejo
    ok_sess = client.post("/api/auth/session", json={"token": settings.auth_token})
    assert ok_sess.status_code == 200
    sess_data = ok_sess.json()
    assert sess_data["authenticated"] is True
    session_token = sess_data["session_token"]
    assert session_token.startswith("saf_sess_")

    # 3. Klic API-ja s sejo prek X-Safeer-Session
    resp = client.get("/api/devices", headers={"X-Safeer-Session": session_token})
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)

    # 4. Klic API-ja s sejo prek Authorization: Bearer
    resp_bearer = client.get("/api/devices", headers={"Authorization": f"Bearer {session_token}"})
    assert resp_bearer.status_code == 200


def test_ws_ticket_generation():
    # Klic za vstopnico zahteva sejo ali avtorizacijo
    resp_unauth = client.post("/api/auth/ws-ticket")
    assert resp_unauth.status_code == 401

    # Z veljavno avtentikacijo prejmemo enokratno vstopnico
    resp = client.post("/api/auth/ws-ticket", headers=AUTH_HEADERS)
    assert resp.status_code == 200
    tkt_data = resp.json()
    assert "ticket" in tkt_data
    assert tkt_data["ticket"].startswith("saf_tkt_")
    assert tkt_data["expires_in_seconds"] == 30


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


def test_portal_and_landing_page():
    resp_portal = client.get("/portal")
    assert resp_portal.status_code == 200
    assert "Safeer Control" in resp_portal.text
    assert "Dual Capability Gates" in resp_portal.text

    resp_landing = client.get("/landing")
    assert resp_landing.status_code == 200
    assert "Safeer Control" in resp_landing.text


def test_installer_script_endpoint():
    resp_install = client.get("/install.sh")
    assert resp_install.status_code == 200
    assert "SAFEER CONTROL" in resp_install.text
    assert "#!/usr/bin/env bash" in resp_install.text


def test_download_endpoints():
    resp_apk = client.get("/download/apk")
    assert resp_apk.status_code == 200
    assert len(resp_apk.content) > 1000000  # APK is ~2.8MB

    resp_tv = client.get("/download/tv-binary")
    assert resp_tv.status_code == 200
    assert len(resp_tv.content) > 1000000  # Go binary is ~7.5MB

    resp_static_apk = client.get("/downloads/SafeerCompanion.apk")
    assert resp_static_apk.status_code == 200

