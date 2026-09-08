"""
Testi za Safeer Control V0.7 — Control UI/CLI + Pairing UX.
Preverja:
1. GET /api/devices/{device_id}/pairing (stanje seznanitve, maskiranje odtisa, health).
2. POST /api/devices/{device_id}/pair (generiranje 256-bitnega ključa in navodil).
3. POST /api/devices/{device_id}/rotate-key (rotacija ključa).
4. POST /api/devices/{device_id}/revoke-key (preklic ključa).
5. CLI ukazi: safeer-control shizuku (status, pair, rotate-key, force-stop, read-setting, clear-cache).
6. Fail-closed vedenje brez avtentikacije (HTTP 401).
"""

import pytest
from fastapi.testclient import TestClient

from app.server import app
from app.cli import cmd_shizuku
from core.config import get_settings
from core.devices.models import Device, DeviceType
from core.devices.registry import get_registry
from core.security.keystore import get_keystore
from providers.shizuku.provider import ShizukuProvider
from providers.shizuku.transport import BaseCompanionTransport, CompanionResponse


class MockTestTransport(BaseCompanionTransport):
    def __init__(self, secret_token=None):
        self.secret_token = secret_token
        self.sent_requests = []

    def send(self, request):
        self.sent_requests.append(request)
        return CompanionResponse(
            request_id=request.request_id,
            capability=request.capability,
            success=True,
            data={"test": "ok", "value": "15"},
            timestamp=1700000000.0
        )

    def check_health(self):
        return True


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def auth_headers():
    cfg = get_settings()
    return {"X-Safeer-Token": cfg.auth_token}


def test_pairing_endpoints_unauthenticated_fails(client):
    """Brez avtentikacije morajo vse pairing točke vrniti HTTP 401."""
    res = client.get("/api/devices/shizuku_companion/pairing")
    assert res.status_code == 401

    res = client.post("/api/devices/shizuku_companion/pair")
    assert res.status_code == 401

    res = client.post("/api/devices/shizuku_companion/rotate-key")
    assert res.status_code == 401

    res = client.post("/api/devices/shizuku_companion/revoke-key")
    assert res.status_code == 401


def test_pairing_endpoints_unknown_device_returns_404(client, auth_headers):
    """Neznana naprava mora vrniti HTTP 404."""
    res = client.get("/api/devices/non_existent_device/pairing", headers=auth_headers)
    assert res.status_code == 404

    res = client.post("/api/devices/non_existent_device/pair", headers=auth_headers)
    assert res.status_code == 404


def test_pairing_endpoints_lifecycle(client, auth_headers):
    """Preveri celoten cikel seznanitve prek API: pair -> get status -> rotate -> revoke."""
    reg = get_registry()
    dev = Device(
        id="shizuku_api_test",
        name="API Test Shizuku",
        type=DeviceType.SHIZUKU,
        host="127.0.0.1",
        port=8995
    )
    mock_transport = MockTestTransport()
    provider = ShizukuProvider(dev, transport=mock_transport)
    reg.register(dev, provider)

    keystore = get_keystore()
    keystore.revoke_key("shizuku_api_test")

    # 1. Začetno stanje: neseznanjeno
    res = client.get("/api/devices/shizuku_api_test/pairing", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["is_paired"] is False
    assert data["key_preview"] is None
    assert data["health"]["healthy"] is True

    # 2. Seznanitev: POST /pair
    res_pair = client.post("/api/devices/shizuku_api_test/pair", headers=auth_headers)
    assert res_pair.status_code == 200
    pair_data = res_pair.json()
    assert pair_data["paired"] is True
    assert len(pair_data["secret_key"]) == 64  # 256 bitov
    assert mock_transport.secret_token == pair_data["secret_key"]
    assert "companion.key" in pair_data["instructions"]

    # 3. Preveri posodobljeno stanje: GET /pairing (ključ je maskiran!)
    res_status = client.get("/api/devices/shizuku_api_test/pairing", headers=auth_headers)
    assert res_status.status_code == 200
    st_data = res_status.json()
    assert st_data["is_paired"] is True
    assert st_data["key_preview"] == f"{pair_data['secret_key'][:8]}...{pair_data['secret_key'][-6:]}"
    assert "secret_key" not in st_data  # Zero Leak Policy!

    # 4. Rotacija: POST /rotate-key
    res_rot = client.post("/api/devices/shizuku_api_test/rotate-key", headers=auth_headers)
    assert res_rot.status_code == 200
    rot_data = res_rot.json()
    assert rot_data["rotated"] is True
    assert rot_data["secret_key"] != pair_data["secret_key"]
    assert mock_transport.secret_token == rot_data["secret_key"]

    # 5. Preklic: POST /revoke-key
    res_rev = client.post("/api/devices/shizuku_api_test/revoke-key", headers=auth_headers)
    assert res_rev.status_code == 200
    assert res_rev.json()["revoked"] is True
    assert mock_transport.secret_token is None


def test_cli_shizuku_commands(capsys):
    """Preveri delovanje vseh CLI ukazov skupine safeer-control shizuku."""
    reg = get_registry()
    dev = Device(
        id="shizuku_cli_test",
        name="CLI Test Shizuku",
        type=DeviceType.SHIZUKU,
        host="127.0.0.1",
        port=8995
    )
    mock_transport = MockTestTransport(secret_token="c" * 64)
    provider = ShizukuProvider(dev, transport=mock_transport)
    reg.register(dev, provider)

    # 1. Pomoč (brez argumentov)
    cmd_shizuku([])
    captured = capsys.readouterr()
    assert "Uporaba: safeer-control shizuku" in captured.out

    # 2. Status
    cmd_shizuku(["status"])
    captured = capsys.readouterr()
    assert "SHIZUKU COMPANION STATUS" in captured.out

    # 3. Seznani (pair)
    cmd_shizuku(["pair", "shizuku_cli_test"])
    captured = capsys.readouterr()
    assert "USPEŠNO SEZNANJENA NAPRAVA: shizuku_cli_test" in captured.out
    assert "256-bitni skrivni ključ" in captured.out

    # 4. Rotiraj ključ
    cmd_shizuku(["rotate-key", "shizuku_cli_test"])
    captured = capsys.readouterr()
    assert "uspešno rotiran" in captured.out

    # 5. Privilegirano dejanje: force-stop
    cmd_shizuku(["force-stop", "com.safeer.mobile.browser"])
    captured = capsys.readouterr()
    assert "Zaustavitev paketa 'com.safeer.mobile.browser'" in captured.out

    # 6. Privilegirano dejanje: read-setting
    cmd_shizuku(["read-setting", "stay_on_while_plugged_in"])
    captured = capsys.readouterr()
    assert "Nastavitev global.stay_on_while_plugged_in" in captured.out

    # 7. Privilegirano dejanje: clear-cache
    cmd_shizuku(["clear-cache", "com.safeer.mobile.browser"])
    captured = capsys.readouterr()
    assert "Predpomnilnik paketa 'com.safeer.mobile.browser'" in captured.out
