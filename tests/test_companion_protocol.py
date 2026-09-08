"""
Varnostni in enotni testi za Safeer Companion (V0.6).
Preverja 4 ključne zaščite:
1. Obvezna HMAC-SHA256 avtentikacija nad kanoničnim nizom.
2. Preverjanje svežine časovnega žiga (timestamp drift).
3. Zaščita pred napadi s ponavljanjem (anti-replay tracker).
4. Strogo ujemanje response.request_id == request.request_id in response.capability == request.capability.
5. Neodvisna izvedba CapabilityGate #2 na Companion strani (Android Meja).
6. Stroga verifikacija zdravja (Companion deluje + Shizuku dovoljenja dodeljena).
7. Celoten End-to-End preizkus s pravim lokalnim Companion daemon strežnikom.
"""

import time
import pytest
import threading
from unittest.mock import patch, MagicMock

from companion.protocol import (
    compute_canonical_string,
    compute_hmac,
    verify_hmac,
    ReplayTracker,
    CompanionRequest,
    CompanionResponse,
    CompanionHealthResponse,
)
from companion.gate import CompanionGate
from companion.runner import ShizukuRunner
from companion.server import create_companion_server
from providers.shizuku.capabilities import Capability
from providers.shizuku.transport import HttpCompanionTransport


def test_canonical_string_and_hmac_signing():
    """Kanonični niz mora biti determinističen, HMAC podpis pa zanesljiv."""
    secret = "test_super_secret_123"
    canon = compute_canonical_string(
        request_id="req-001",
        timestamp=1700000000.0,
        nonce="nonce-abc",
        capability="app.force_stop",
        params={"package": "com.example.safeerbrowser"}
    )
    assert canon == "req-001:1700000000:nonce-abc:app.force_stop:{\"package\":\"com.example.safeerbrowser\"}"

    sig = compute_hmac(secret, canon)
    assert verify_hmac(secret, canon, sig) is True
    # Sprememba podatkov mora takoj zlomiti verifikacijo
    assert verify_hmac(secret, canon + "tampered", sig) is False
    assert verify_hmac("wrong_secret", canon, sig) is False


def test_replay_tracker_blocks_replays_and_stale_timestamps():
    """ReplayTracker mora ujeti ponovljene zahteve in časovni zamik."""
    tracker = ReplayTracker(window_seconds=10.0)
    now = time.time()

    # 1. Veljavna nova zahteva
    ok, _ = tracker.check_and_record("req-1", "nonce-1", now)
    assert ok is True

    # 2. Napad s ponavljanjem (isti request_id in nonce)
    ok, msg = tracker.check_and_record("req-1", "nonce-1", now)
    assert ok is False
    assert "Replay" in msg

    # 3. Zastarela zahteva (zamuda > 10s)
    ok, msg = tracker.check_and_record("req-2", "nonce-2", now - 25.0)
    assert ok is False
    assert "potekla" in msg or "drift" in msg

    # 4. Zahteva iz prihodnosti (> 10s vnaprej)
    ok, msg = tracker.check_and_record("req-3", "nonce-3", now + 25.0)
    assert ok is False
    assert "potekla" in msg or "drift" in msg


def test_companion_gate_enforces_android_side_boundary():
    """CompanionGate (Gate #2) mora samostojno zavrniti nepooblaščene zahteve."""
    # 1. Zaščiten sistemski paket
    ok, reason = CompanionGate.require(Capability.APP_FORCE_STOP, {"package": "com.android.systemui"})
    assert ok is False
    assert "zaščitenega" in reason

    # 2. Neznana aplikacija
    ok, reason = CompanionGate.require(Capability.APP_FORCE_STOP, {"package": "com.evil.trojan"})
    assert ok is False
    assert "nepooblaščen" in reason

    # 3. Neavtoriziran ključ nastavitve
    ok, reason = CompanionGate.require(Capability.SETTINGS_READ, {"namespace": "secure", "key": "private_pin"})
    assert ok is False
    assert "ni na seznamu" in reason

    # 4. Poskus vbrizgavanja poljubnega polja
    ok, reason = CompanionGate.require(Capability.APP_FORCE_STOP, {"package": "com.example.safeerbrowser", "exec": "id"})
    assert ok is False
    assert "Varnostna kršitev" in reason

    # 5. Odobrena operacija
    ok, reason = CompanionGate.require(Capability.APP_FORCE_STOP, {"package": "com.example.safeerbrowser"})
    assert ok is True


def test_transport_rejects_mismatched_response_fields():
    """Transport mora takoj zavrniti odziv, ki ne ustreza request_id ali capability (V0.6 zaščita #4)."""
    transport = HttpCompanionTransport(host="127.0.0.1", port=8995, secret_token="sec")
    req = CompanionRequest(
        request_id="req-expected-123",
        capability=Capability.APP_FORCE_STOP,
        params={"package": "com.example.safeerbrowser"}
    )

    # 1. Server vrne napačen request_id
    bad_id_resp = MagicMock()
    bad_id_resp.status = 200
    bad_id_resp.read.return_value = b'{"request_id": "req-WRONG", "capability": "app.force_stop", "success": true}'
    bad_id_resp.__enter__.return_value = bad_id_resp

    with patch("urllib.request.OpenerDirector.open", return_value=bad_id_resp):
        res = transport.send(req)
        assert res.success is False
        assert "Mismatched request_id" in res.error_message

    # 2. Server vrne napačen capability
    bad_cap_resp = MagicMock()
    bad_cap_resp.status = 200
    bad_cap_resp.read.return_value = b'{"request_id": "req-expected-123", "capability": "settings.read", "success": true}'
    bad_cap_resp.__enter__.return_value = bad_cap_resp

    with patch("urllib.request.OpenerDirector.open", return_value=bad_cap_resp):
        res = transport.send(req)
        assert res.success is False
        assert "Mismatched capability" in res.error_message


def test_transport_health_check_requires_shizuku_permissions():
    """Health check mora zahtevati, da je Companion aktiven IN da ima dodeljena Shizuku dovoljenja."""
    transport = HttpCompanionTransport(host="127.0.0.1", port=8995)

    # 1. Companion teče, ampak Shizuku nima dovoljenj -> False
    no_perm_resp = MagicMock()
    no_perm_resp.status = 200
    no_perm_resp.read.return_value = b'{"status": "ok", "companion_running": true, "shizuku_available": true, "shizuku_permission_granted": false}'
    no_perm_resp.__enter__.return_value = no_perm_resp

    with patch("urllib.request.OpenerDirector.open", return_value=no_perm_resp):
        assert transport.check_health() is False

    # 2. Vse aktivno -> True
    all_ok_resp = MagicMock()
    all_ok_resp.status = 200
    all_ok_resp.read.return_value = b'{"status": "ok", "companion_running": true, "shizuku_available": true, "shizuku_permission_granted": true}'
    all_ok_resp.__enter__.return_value = all_ok_resp

    with patch("urllib.request.OpenerDirector.open", return_value=all_ok_resp):
        assert transport.check_health() is True


def test_end_to_end_companion_server_handshake():
    """
    Celovit End-to-End preizkus z zagonom lokalnega Companion strežnika:
    1. Avtentikacija s HMAC uspešna
    2. Napačen HMAC zavrnjen (HTTP 401)
    3. Replay zavrnjen (HTTP 400)
    4. Zaščiten sistemski paket zavrnjen s strani Gate #2 (HTTP 403)
    """
    secret = "companion_e2e_secret_token_999"
    test_port = 18995

    # Zaženi lokalni Companion daemon v ozadju
    server = create_companion_server(host="127.0.0.1", port=test_port, secret_key=secret)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.1)

    try:
        transport = HttpCompanionTransport(host="127.0.0.1", port=test_port, secret_token=secret)

        # 1. Uspešna podpisana zahteva za odobreno aplikacijo
        req1 = CompanionRequest(
            capability=Capability.APP_FORCE_STOP,
            params={"package": "com.example.safeerbrowser"}
        )
        resp1 = transport.send(req1)
        assert resp1.success is True
        assert resp1.request_id == req1.request_id
        assert resp1.capability == Capability.APP_FORCE_STOP.value

        # 2. Replay iste zahteve mora strežnik zavrniti
        resp1_replay = transport.send(req1)
        assert resp1_replay.success is False
        assert "Anti-Replay" in resp1_replay.error_message or "HTTP 400" in resp1_replay.error_message

        # 3. Napačen HMAC ključ mora strežnik zavrniti (HTTP 401)
        bad_transport = HttpCompanionTransport(host="127.0.0.1", port=test_port, secret_token="wrong_secret")
        req2 = CompanionRequest(
            capability=Capability.SETTINGS_READ,
            params={"namespace": "global", "key": "stay_on_while_plugged_in"}
        )
        resp2 = bad_transport.send(req2)
        assert resp2.success is False
        assert "HTTP 401" in resp2.error_message or "HMAC" in resp2.error_message

        # 4. Poskus zaustavitve zaščitene sistemske aplikacije mora Gate #2 zavrniti (HTTP 403)
        req3 = CompanionRequest(
            capability=Capability.APP_FORCE_STOP,
            params={"package": "com.android.systemui"}
        )
        resp3 = transport.send(req3)
        assert resp3.success is False
        assert "HTTP 403" in resp3.error_message or "Gate #2" in resp3.error_message

    finally:
        server.shutdown()
        server.server_close()
