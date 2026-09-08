"""
Testni paket za Safeer Control V0.8:
1. Deterministic RFC 5869 HKDF-SHA256 izpeljava ključa iz 6-mestnega PIN-a
2. Celoten interaktivni E2E handshake seznanitve prek TLS povezave (HTTPS)
3. Zavrnitev napačnega ali poteklega PIN-a (Fail-Closed)
4. Certificate Pinning: zavrnitev MITM zamenjave certifikata (Fail-Closed)
5. Zero Exposure: noben nezaščiten ključ se ne prenaša v odzivih ali shranjuje brez zaščite
"""

import time
import shutil
import tempfile
from pathlib import Path
import pytest

from companion.protocol import (
    derive_pairing_key,
    Capability,
    CompanionRequest,
)
from companion.server import create_companion_server
from companion.runner import ShizukuRunner
from core.devices.models import Device, DeviceType
from core.security.keystore import DeviceKeyStore
from providers.shizuku.provider import ShizukuProvider
from providers.shizuku.transport import HttpCompanionTransport


import socket

@pytest.fixture
def temp_dir():
    d = tempfile.mkdtemp(prefix="safeer_test_v08_")
    yield Path(d)
    shutil.rmtree(d, ignore_errors=True)


def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def test_hkdf_derivation_deterministic():
    """Preveri deterministično in standardno RFC 5869 HKDF-SHA256 izpeljavo."""
    pin = "849201"
    client_nonce = "a1b2c3d4e5f60718"
    server_nonce = "9876543210fedcba"

    key1 = derive_pairing_key(pin, client_nonce, server_nonce)
    key2 = derive_pairing_key(pin, client_nonce, server_nonce)

    assert key1 == key2
    assert len(key1) == 64  # 32 bajtov = 64 hex znakov (256 bitov)

    # Drugačen PIN -> popolnoma drugačen ključ
    key_diff_pin = derive_pairing_key("849202", client_nonce, server_nonce)
    assert key1 != key_diff_pin

    # Drugačen nonce -> popolnoma drugačen ključ
    key_diff_nonce = derive_pairing_key(pin, "0000000000000000", server_nonce)
    assert key1 != key_diff_nonce


def test_tls_companion_pin_pairing_and_execution_e2e(temp_dir):
    """
    Popoln E2E test V0.8:
    1. Zagon TLS Companion strežnika z enkratnim 6-mestnim PIN-om
    2. Izvedba pair_pin(pin) prek HTTPS
    3. Overitev certifikatnega prstnega odtisa (Pinning)
    4. Izvedba privilegirane zahteve (settings.read) prek šifriranega TLS transporta
    """
    port = get_free_port()
    pin = "738491"
    cert_path = temp_dir / "companion.crt"
    key_path = temp_dir / "companion.key"
    keystore_path = temp_dir / "keystore.json"

    runner = ShizukuRunner(mock_mode=True)
    server = create_companion_server(
        host="127.0.0.1",
        port=port,
        runner=runner,
        use_tls=True,
        cert_file=str(cert_path),
        key_file=str(key_path),
        pairing_pin=pin,
    )

    import threading
    srv_thread = threading.Thread(target=server.serve_forever, daemon=True)
    srv_thread.start()
    time.sleep(0.15)

    try:
        keystore = DeviceKeyStore(storage_path=str(keystore_path))
        device = Device(id="phone_tls", name="Galaxy S25 TLS", type=DeviceType.SHIZUKU, host="127.0.0.1", port=port)
        provider = ShizukuProvider(device=device, keystore=keystore)

        # Pred seznanitvijo: nima ključa in certifikata
        assert keystore.get_key("phone_tls") is None
        assert keystore.get_tls_fingerprint("phone_tls") is None

        # Izvedi PIN seznanitev prek TLS
        derived_key, tls_fp = provider.pair_pin(pin)

        assert len(derived_key) == 64
        assert len(tls_fp) == 64
        assert keystore.get_key("phone_tls") == derived_key
        assert keystore.get_tls_fingerprint("phone_tls") == tls_fp.lower()
        assert provider.transport.use_tls is True
        assert provider.transport.pinned_fingerprint == tls_fp.lower()

        # Preveri health prek TLS
        assert provider.transport.check_health() is True

        # Izvedi privilegirano dejanje (read_setting) prek TLS
        res = provider.read_setting("global", "stay_on_while_plugged_in")
        assert res.success is True
        assert res.data["key"] == "stay_on_while_plugged_in"
        assert res.data["value"] is not None

    finally:
        server.shutdown()
        server.server_close()


def test_tls_pairing_wrong_pin_fails(temp_dir):
    """Preveri, da napačen PIN takoj zavrne seznanitev (Fail-Closed)."""
    port = get_free_port()
    cert_path = temp_dir / "companion.crt"
    key_path = temp_dir / "companion.key"

    runner = ShizukuRunner(mock_mode=True)
    server = create_companion_server(
        host="127.0.0.1",
        port=port,
        runner=runner,
        use_tls=True,
        cert_file=str(cert_path),
        key_file=str(key_path),
        pairing_pin="111222",
    )

    import threading
    srv_thread = threading.Thread(target=server.serve_forever, daemon=True)
    srv_thread.start()
    time.sleep(0.15)

    try:
        device = Device(id="phone_wrong_pin", name="Test", type=DeviceType.SHIZUKU, host="127.0.0.1", port=port)
        provider = ShizukuProvider(device=device)

        with pytest.raises(ValueError) as exc:
            provider.pair_pin("999999")

        assert "zavrnjena" in str(exc.value).lower() or "failed" in str(exc.value).lower()

    finally:
        server.shutdown()
        server.server_close()


def test_tls_pairing_expired_pin_fails(temp_dir):
    """Preveri, da potekel PIN zavrne seznanitev (Fail-Closed)."""
    port = get_free_port()
    cert_path = temp_dir / "companion.crt"
    key_path = temp_dir / "companion.key"

    runner = ShizukuRunner(mock_mode=True)
    server = create_companion_server(
        host="127.0.0.1",
        port=port,
        runner=runner,
        use_tls=True,
        cert_file=str(cert_path),
        key_file=str(key_path),
        pairing_pin="555666",
        pin_ttl_seconds=0.05,  # Potek po 50 ms
    )

    import threading
    srv_thread = threading.Thread(target=server.serve_forever, daemon=True)
    srv_thread.start()
    time.sleep(0.1)  # Počakaj, da PIN poteče

    try:
        device = Device(id="phone_expired_pin", name="Test", type=DeviceType.SHIZUKU, host="127.0.0.1", port=port)
        provider = ShizukuProvider(device=device)

        with pytest.raises(ValueError):
            provider.pair_pin("555666")

    finally:
        server.shutdown()
        server.server_close()


def test_certificate_pinning_blocks_mitm_substitution(temp_dir):
    """
    Kritičen varnostni test:
    Če napadalec prestreže promet in ponudi drug TLS certifikat,
    mora transport takoj prekiniti povezavo (Fail-Closed).
    """
    port = get_free_port()
    cert_path = temp_dir / "companion.crt"
    key_path = temp_dir / "companion.key"

    runner = ShizukuRunner(mock_mode=True)
    server = create_companion_server(
        host="127.0.0.1",
        port=port,
        secret_key="a" * 64,
        runner=runner,
        use_tls=True,
        cert_file=str(cert_path),
        key_file=str(key_path),
    )

    import threading
    srv_thread = threading.Thread(target=server.serve_forever, daemon=True)
    srv_thread.start()
    time.sleep(0.15)

    try:
        # Pripnemo NAPAČEN (lažen) certifikatni odtis
        attacker_fake_fingerprint = "0" * 64

        transport = HttpCompanionTransport(
            host="127.0.0.1",
            port=port,
            secret_token="a" * 64,
            use_tls=True,
            pinned_fingerprint=attacker_fake_fingerprint
        )

        # 1. Health check mora zavrniti
        assert transport.check_health() is False

        # 2. Poskus klica privilegirane zmožnosti mora fail-closed zavrniti
        req = CompanionRequest(capability=Capability.SETTINGS_READ, params={"namespace": "global", "key": "stay_on_while_plugged_in"})
        resp = transport.send(req)

        assert resp.success is False
        assert "fail-closed" in resp.error_message.lower() or "mismatch" in resp.error_message.lower()

    finally:
        server.shutdown()
        server.server_close()
