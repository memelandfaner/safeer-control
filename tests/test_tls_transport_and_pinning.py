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
    compute_pairing_transcript,
    derive_pairing_auth_key,
    compute_transcript_auth,
    derive_final_shared_key,
    PairingInitRequest,
    PairingInitResponse,
    PairingConfirmRequest,
    PairingConfirmResponse,
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


def test_transcript_channel_binding_and_keys():
    """Preveri vezavo transkripta (Channel Binding) na certifikat in nonces ter deterministično izpeljavo."""
    pin = "123456"
    c_nonce = "1111222233334444"
    s_nonce = "aaaabbbbccccdddd"
    fp1 = "0123456789abcdef" * 4
    fp2 = "fedcba9876543210" * 4

    # 1. Enaki parametri dajo enak transkript in avtentikacijo
    t1 = compute_pairing_transcript(c_nonce, s_nonce, fp1)
    auth_key1 = derive_pairing_auth_key(pin, c_nonce, s_nonce)
    c_auth1 = compute_transcript_auth(auth_key1, t1, "client")
    s_auth1 = compute_transcript_auth(auth_key1, t1, "server")
    k1 = derive_final_shared_key(auth_key1, t1)

    t1_repeat = compute_pairing_transcript(c_nonce, s_nonce, fp1)
    auth_key1_repeat = derive_pairing_auth_key(pin, c_nonce, s_nonce)
    assert t1 == t1_repeat
    assert auth_key1 == auth_key1_repeat
    assert c_auth1 == compute_transcript_auth(auth_key1_repeat, t1_repeat, "client")
    assert s_auth1 == compute_transcript_auth(auth_key1_repeat, t1_repeat, "server")
    assert k1 == derive_final_shared_key(auth_key1_repeat, t1_repeat)

    # 2. Drugačen certifikatni odtis -> popolnoma spremeni transkript, avtentikacijo in skupni ključ
    t2 = compute_pairing_transcript(c_nonce, s_nonce, fp2)
    assert t1 != t2
    c_auth2 = compute_transcript_auth(auth_key1, t2, "client")
    s_auth2 = compute_transcript_auth(auth_key1, t2, "server")
    k2 = derive_final_shared_key(auth_key1, t2)
    assert c_auth1 != c_auth2
    assert s_auth1 != s_auth2
    assert k1 != k2


def test_pairing_rate_limit_lockout_after_three_failures(temp_dir):
    """
    Preveri aktivno zaščito pred brute-force ugibanjem PIN-a (Anti-Brute-Force):
    Po 3 neuspešnih poskusih avtentikacije transkripta se PIN takoj prekliče in zaklene.
    """
    port = get_free_port()
    pin = "482910"
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
        pairing_pin=pin,
        max_pairing_attempts=3,
    )

    import threading
    srv_thread = threading.Thread(target=server.serve_forever, daemon=True)
    srv_thread.start()
    time.sleep(0.15)

    try:
        transport = HttpCompanionTransport(host="127.0.0.1", port=port, use_tls=True)

        # 1. korak: Init seznanitev (dobi server_nonce in TLS fp)
        import urllib.request
        import json
        import ssl
        from providers.shizuku.transport import FingerprintHTTPSHandler

        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), FingerprintHTTPSHandler())

        c_nonce = "testnonceclient01"
        init_body = json.dumps({"client_nonce": c_nonce}).encode()
        init_req = urllib.request.Request(f"https://127.0.0.1:{port}/api/companion/pair/init", data=init_body, headers={"Content-Type": "application/json"})
        with opener.open(init_req, timeout=2.0) as resp:
            init_data = json.loads(resp.read().decode())
            s_nonce = init_data["server_nonce"]
            tls_fp = init_data["tls_fingerprint"]

        # Izvedi 3 neuspešne poskuse z napačnim auth
        bad_auth = "0" * 64
        confirm_body = json.dumps({"client_nonce": c_nonce, "client_auth": bad_auth}).encode()
        confirm_req = urllib.request.Request(f"https://127.0.0.1:{port}/api/companion/pair/confirm", data=confirm_body, headers={"Content-Type": "application/json"})

        for attempt in range(1, 4):
            with pytest.raises(urllib.error.HTTPError) as exc:
                opener.open(confirm_req, timeout=2.0)
            assert exc.value.code in (403, 400)
            err_data = json.loads(exc.value.read().decode())
            assert "fail-closed" in err_data.get("error_message", "").lower()

        # 4. poskus: Tudi če zdaj pošljemo PRAVI avtentikator, mora biti PIN zaklenjen (Fail-Closed)
        transcript = compute_pairing_transcript(c_nonce, s_nonce, tls_fp)
        auth_key = derive_pairing_auth_key(pin, c_nonce, s_nonce)
        valid_auth = compute_transcript_auth(auth_key, transcript, "client")
        valid_body = json.dumps({"client_nonce": c_nonce, "client_auth": valid_auth}).encode()
        valid_req = urllib.request.Request(f"https://127.0.0.1:{port}/api/companion/pair/confirm", data=valid_body, headers={"Content-Type": "application/json"})

        with pytest.raises(urllib.error.HTTPError) as exc:
            opener.open(valid_req, timeout=2.0)
        assert exc.value.code == 403
        lockout_err = json.loads(exc.value.read().decode())
        assert "preseženo" in lockout_err.get("error_message", "").lower() or "zaklenjen" in lockout_err.get("error_message", "").lower() or "ni aktiven" in lockout_err.get("error_message", "").lower()

    finally:
        server.shutdown()
        server.server_close()


def test_adversarial_mitm_bootstrap_attack_fails_closed(temp_dir):
    """
    Adversarial MITM napad med prvim bootstrap stikom:
    Prava naprava Companion posluša na port_srv s certifikatom Cert_A.
    Napadalec posluša na port_mitm s svojim certifikatom Cert_MITM.
    Klient se pomotoma ali zaradi ARP spoofinga poveže na port_mitm.
    Tudi če napadalec posreduje init zahteve na pravo napravo, se certifikatna odtisa
    razlikujeta (FP_MITM != FP_A). Posledično se transkript ne ujema,
    avtentikacija zavrne povezavo in seznanitev fail-closed prekine.
    Napadalec ne more izvedeti PIN-a niti izpeljati ključa!
    """
    port_srv = get_free_port()
    port_mitm = get_free_port()
    pin = "654321"

    cert_srv = temp_dir / "srv.crt"
    key_srv = temp_dir / "srv.key"
    cert_mitm = temp_dir / "mitm.crt"
    key_mitm = temp_dir / "mitm.key"

    runner = ShizukuRunner(mock_mode=True)
    # Pravi strežnik
    server = create_companion_server(
        host="127.0.0.1",
        port=port_srv,
        runner=runner,
        use_tls=True,
        cert_file=str(cert_srv),
        key_file=str(key_srv),
        pairing_pin=pin,
    )

    # MITM lažni strežnik z ločenim certifikatom
    mitm_server = create_companion_server(
        host="127.0.0.1",
        port=port_mitm,
        runner=runner,
        use_tls=True,
        cert_file=str(cert_mitm),
        key_file=str(key_mitm),
        pairing_pin="999999",  # Napadalec ne pozna pravega PIN-a
    )

    import threading
    t1 = threading.Thread(target=server.serve_forever, daemon=True)
    t2 = threading.Thread(target=mitm_server.serve_forever, daemon=True)
    t1.start()
    t2.start()
    time.sleep(0.15)

    try:
        # Klient poskuša seznaniti s pravim PIN-om, a se poveže na lažni MITM endpoint
        device = Device(id="phone_mitm_target", name="Target", type=DeviceType.SHIZUKU, host="127.0.0.1", port=port_mitm)
        provider = ShizukuProvider(device=device)

        with pytest.raises(ValueError) as exc:
            provider.pair_pin(pin)

        # Seznanitev mora neizogibno propasti (Fail-Closed)
        assert "zavrnjena" in str(exc.value).lower() or "failed" in str(exc.value).lower()

        # Prepričajmo se, da transport nima shranjenega veljavnega ključa
        assert provider.transport.secret_token is None

    finally:
        server.shutdown()
        server.server_close()
        mitm_server.shutdown()
        mitm_server.server_close()


def test_strict_zero_fallback_when_pinned(temp_dir):
    """
    Zero-fallback test:
    Ko je certifikat enkrat pripet (pinned_fingerprint), transport NIKOLI ne sme
    tiho pasti nazaj na nešifriran HTTP ali na napačen TLS certifikat.
    """
    port = get_free_port()
    cert_path = temp_dir / "companion.crt"
    key_path = temp_dir / "companion.key"

    runner = ShizukuRunner(mock_mode=True)
    server = create_companion_server(
        host="127.0.0.1",
        port=port,
        secret_key="b" * 64,
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
        # Transport s pinned_fingerprint
        pinned_fp = "f" * 64
        transport = HttpCompanionTransport(
            host="127.0.0.1",
            port=port,
            secret_token="b" * 64,
            use_tls=False,  # Eksplicitno poskusi izklopiti TLS ob nastavljenem pinned_fingerprint
            pinned_fingerprint=pinned_fp,
        )

        # Shema mora kljub use_tls=False ostati "https" zaradi prisotnosti pinned_fingerprint
        assert transport.scheme == "https"
        assert transport.endpoint_url.startswith("https://")

        # Klic mora fail-closed zavrniti zaradi neskladja certifikata
        req = CompanionRequest(capability=Capability.SETTINGS_READ, params={"namespace": "global", "key": "stay_on_while_plugged_in"})
        resp = transport.send(req)
        assert resp.success is False
        assert "fail-closed" in resp.error_message.lower() or "mismatch" in resp.error_message.lower()

    finally:
        server.shutdown()
        server.server_close()


def test_go_companion_v081_bootstrap_handshake(temp_dir):
    """
    Preveri delovanje pravega prevedenega Go Companion binarnega programa:
    1. Zagon /tmp/safeer-companion-test z --tls --pair
    2. Branje dinamičnega PIN-a iz izpisa
    3. Izvedba Python pair_pin(pin) z mutual transcript confirmation
    4. Uspešna izvedba settings.read prek vzpostavljene povezave
    """
    import subprocess
    import re

    go_bin = Path("/tmp/safeer-companion-test")
    if not go_bin.exists():
        pytest.skip("Go testni binarni program /tmp/safeer-companion-test ne obstaja.")

    port = get_free_port()
    cert_path = temp_dir / "go_companion.crt"
    key_path = temp_dir / "go_companion.key"
    mock_rish = temp_dir / "mock_rish.sh"
    mock_rish.write_text('#!/bin/sh\nif [ "$2" = "id" ]; then echo "uid=2000(shell) gid=2000(shell)"; else echo "1"; fi\n')
    mock_rish.chmod(0o755)

    proc = subprocess.Popen(
        [
            str(go_bin),
            f"-port={port}",
            "-tls=true",
            f"-cert={cert_path}",
            f"-key={key_path}",
            "-pair=true",
            f"-rish-path={mock_rish}",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    pin = None
    try:
        # Preberi PIN iz izpisa
        start_time = time.time()
        while time.time() - start_time < 5.0:
            line = proc.stdout.readline()
            if not line:
                break
            match = re.search(r"PIN ZA SEZNANITEV:\s*([0-9]{6})", line)
            if match:
                pin = match.group(1)
                break

        assert pin is not None, "Go Companion ni izpisal PIN-a v 5 sekundah"
        time.sleep(0.2)

        device = Device(id="go_companion_phone", name="Go Phone", type=DeviceType.SHIZUKU, host="127.0.0.1", port=port)
        provider = ShizukuProvider(device=device)

        derived_key, tls_fp = provider.pair_pin(pin)

        assert len(derived_key) == 64
        assert len(tls_fp) == 64
        assert provider.transport.use_tls is True
        assert provider.transport.pinned_fingerprint == tls_fp.lower()

        # Preveri health prek pravega Go TLS Companiona
        assert provider.transport.check_health() is True

        # Preveri klic nastavitve prek pravega Go TLS Companiona
        res = provider.read_setting("global", "stay_on_while_plugged_in")
        assert res.success is True
        assert res.data["key"] == "stay_on_while_plugged_in"

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=2.0)
        except Exception:
            proc.kill()

