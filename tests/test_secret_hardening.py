"""
Testi za V0.6.2 (Device Pairing & Secret Hardening).
Preverja:
1. DeviceKeyStore generira unikatne 256-bitne ključe in jih varno hrani (0600).
2. Rotacija in preklic ključev.
3. Zavrnitev privzetih ali prekratkih ključev (< 32 bajtov / 256 bitov) v protokolu.
4. Fail-closed obnašanje transporta ob manjkajočem ključu.
5. Fail-closed odziv Companion strežnika (HTTP 503), če ključ ni nastavljen.
6. Čista semantika app.cache_maintenance (samo ciljni paket).
"""

import os
import stat
import tempfile
import threading
import time
import pytest

from core.security.keystore import DeviceKeyStore
from companion.protocol import compute_canonical_string, compute_hmac, verify_hmac, Capability
from companion.server import create_companion_server
from companion.runner import ShizukuRunner
from providers.shizuku.transport import HttpCompanionTransport, CompanionRequest


def test_keystore_generates_256bit_keys_with_secure_permissions():
    """DeviceKeyStore mora generirati 256-bitne (64 hex) ključe in datoteko zakleniti na 0600."""
    with tempfile.TemporaryDirectory() as tmpdir:
        key_file = os.path.join(tmpdir, "test_keys.json")
        store = DeviceKeyStore(storage_path=key_file)

        key1 = store.get_or_create_key("phone_s25")
        assert len(key1) == 64  # 64 hex znakov = 256 bitov
        assert isinstance(key1, str)

        # Preveri pravice datoteke (0600 = uporabnik rw, ostali nič)
        file_stat = os.stat(key_file)
        file_mode = stat.S_IMODE(file_stat.st_mode)
        assert file_mode == 0o600

        # Ob ponovnem klicu mora vrniti enak ključ
        key1_cached = store.get_key("phone_s25")
        assert key1_cached == key1

        # Druga naprava mora dobiti drugačen unikatni ključ
        key2 = store.get_or_create_key("tv_philips")
        assert key2 != key1
        assert len(key2) == 64


def test_keystore_rotation_and_revocation():
    """Rotacija mora nadomestiti stari ključ z novim, preklic pa ga izbrisati."""
    with tempfile.TemporaryDirectory() as tmpdir:
        key_file = os.path.join(tmpdir, "test_keys.json")
        store = DeviceKeyStore(storage_path=key_file)

        old_key = store.get_or_create_key("device_abc")
        new_key = store.rotate_key("device_abc")
        assert new_key != old_key
        assert store.get_key("device_abc") == new_key

        # Preklic
        revoked = store.revoke_key("device_abc")
        assert revoked is True
        assert store.get_key("device_abc") is None
        assert store.revoke_key("device_abc") is False


def test_keystore_set_key_validation():
    """set_key mora centralno uveljaviti minimalno dolžino ključa (256 bitov) in zavrniti neveljavne kandidate."""
    with tempfile.TemporaryDirectory() as tmpdir:
        key_file = os.path.join(tmpdir, "test_keys.json")
        store = DeviceKeyStore(storage_path=key_file)

        # 1. Prekratek ključ mora sprožiti ValueError
        with pytest.raises(ValueError):
            store.set_key("dev_1", "too_short")

        with pytest.raises(ValueError):
            store.set_key("dev_1", "")

        # 2. Veljaven 32-bajtni ključ se uspešno shrani
        valid_key = "x" * 32
        store.set_key("dev_1", valid_key)
        assert store.get_key("dev_1") == valid_key

        # 3. Veljaven 64-hex ključ
        hex_key = "a" * 64
        store.set_key("dev_2", hex_key)
        assert store.get_key("dev_2") == hex_key


def test_protocol_enforces_minimum_256bit_secret():
    """compute_hmac in verify_hmac morata zavrniti ključe, krajše od 32 znakov."""
    short_secret = "short_secret_123"  # 16 znakov
    valid_secret = "a" * 32           # 32 znakov (256 bitov)

    canon = compute_canonical_string("req-1", 1700000000.0, "nonce-1", "settings.read", {"namespace": "global", "key": "device_name"})

    # Prekratek ključ mora sprožiti ValueError
    with pytest.raises(ValueError) as exc:
        compute_hmac(short_secret, canon)
    assert "256 bitov" in str(exc.value)

    # Prazen ključ
    with pytest.raises(ValueError):
        compute_hmac("", canon)

    # Veljaven 32+ znakov ključ mora delovati
    sig = compute_hmac(valid_secret, canon)
    assert verify_hmac(valid_secret, canon, sig) is True

    # Preverjanje z napačnim/kratkim ključem mora vrniti False
    assert verify_hmac(short_secret, canon, sig) is False
    assert verify_hmac("", canon, sig) is False


def test_transport_fail_closed_when_secret_missing_or_short():
    """HttpCompanionTransport mora fail-closed zavrniti zahteve, če ključ ni konfiguriran."""
    # 1. Brez ključa
    t_no_secret = HttpCompanionTransport(host="127.0.0.1", port=8995, secret_token=None)
    req = CompanionRequest(capability=Capability.SETTINGS_READ, params={"namespace": "global", "key": "device_name"})
    res1 = t_no_secret.send(req)
    assert res1.success is False
    assert "Fail-closed" in res1.error_message
    assert "pairing required" in res1.error_message.lower()

    # 2. Prekratek ključ
    t_short_secret = HttpCompanionTransport(host="127.0.0.1", port=8995, secret_token="too_short")
    res2 = t_short_secret.send(req)
    assert res2.success is False
    assert "Fail-closed" in res2.error_message


def test_companion_server_fail_closed_without_valid_secret():
    """Companion strežnik mora vrniti HTTP 503, če teče brez nastavljenega 256-bitnega ključa."""
    test_port = 18996
    mock_runner = ShizukuRunner(mock_mode=True)
    # Zagon strežnika brez ključa
    server = create_companion_server(host="127.0.0.1", port=test_port, secret_key="", runner=mock_runner)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.1)

    try:
        # Odjemalec poskuša klic z nekim ključem
        client_secret = "b" * 32
        transport = HttpCompanionTransport(host="127.0.0.1", port=test_port, secret_token=client_secret)
        req = CompanionRequest(capability=Capability.APP_FORCE_STOP, params={"package": "com.example.safeerbrowser"})
        resp = transport.send(req)

        assert resp.success is False
        assert "HTTP 503" in resp.error_message or "503" in resp.error_message
    finally:
        server.shutdown()
        server.server_close()


def test_app_cache_maintenance_semantics():
    """APP_CACHE_MAINTENANCE mora ciljati izključno predpomnilnik navedenega paketa."""
    recorded_cmds = []

    def executor(cmd):
        recorded_cmds.append(cmd)
        return 0, "", ""

    runner = ShizukuRunner(rish_path="/dummy/rish", executor=executor)
    runner._shizuku_available = True
    runner._permission_granted = True
    runner._execution_mode = "rish"

    ok, msg, data = runner.execute_capability(
        Capability.APP_CACHE_MAINTENANCE,
        {"package": "com.example.safeerbrowser"}
    )
    assert ok is True
    assert data["cache_cleared"] is True

    # Preveri, da ni bil klican globalni pm trim-caches
    for cmd in recorded_cmds:
        cmd_str = " ".join(cmd)
        assert "pm trim-caches" not in cmd_str, "pm trim-caches ne sme biti klican v paketnem cache_maintenance!"
    assert any("/sdcard/Android/data/com.example.safeerbrowser/cache/*" in " ".join(cmd) for cmd in recorded_cmds)


def test_shizuku_provider_keystore_binding_and_rotation():
    """ShizukuProvider mora avtomatsko povezati DeviceKeyStore s transportom in podpirati rotacijo."""
    from core.devices.models import Device, DeviceType
    from providers.shizuku.provider import ShizukuProvider

    with tempfile.TemporaryDirectory() as tmpdir:
        key_file = os.path.join(tmpdir, "test_keys.json")
        store = DeviceKeyStore(storage_path=key_file)

        # 1. Ustvari napravo in ponudnika z vbrizganim KeyStore
        dev = Device(
            id="samsung_s25_test",
            name="Samsung S25",
            type=DeviceType.SHIZUKU,
            host="127.0.0.1",
            port=8995
        )
        provider = ShizukuProvider(dev, keystore=store)

        # Brez seznanitve transport nima ključa
        assert provider.transport.secret_token is None

        # 2. Seznanitev naprave
        paired_key = provider.pair()
        assert len(paired_key) == 64
        assert provider.transport.secret_token == paired_key
        assert store.get_key("samsung_s25_test") == paired_key

        # 3. Rotacija ključa
        rotated_key = provider.rotate_secret()
        assert len(rotated_key) == 64
        assert rotated_key != paired_key
        assert provider.transport.secret_token == rotated_key
        assert store.get_key("samsung_s25_test") == rotated_key

        # 4. Ponovno ustvarjen ponudnik za isto napravo naloži shranjen ključ
        provider2 = ShizukuProvider(dev, keystore=store)
        assert provider2.transport.secret_token == rotated_key

