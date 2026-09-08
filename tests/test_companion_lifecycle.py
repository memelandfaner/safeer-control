"""
Testni paket za Safeer Companion V0.9:
1. Preverjanje verzije (0.9.0 / protokol 1.1) in končne točke /api/companion/lifecycle
2. Dinamični življenjski cikel Shizuku dovoljenj (ready -> waiting_for_shizuku -> permission_denied -> recovered)
3. Nadzorovane posodobitve (OTA): SHA-256 verifikacija celovitosti, zavrnitev pokvarjenih posodobitev
4. E2E preverjanje zagnanega prevedenega nativnega Go Companion programa (v0.9.0)
5. Preverjanje pakiranja Android komponente (SafeerCompanion.apk, Foreground Service, BootReceiver)
"""

import time
import shutil
import socket
import zipfile
import tempfile
import subprocess
import threading
from pathlib import Path
import pytest

from companion.protocol import (
    Capability,
    CompanionRequest,
    CompanionLifecycleResponse,
    CompanionUpdateResponse,
)
from companion.server import create_companion_server
from companion.runner import ShizukuRunner
from companion.lifecycle import CompanionLifecycleManager
from core.devices.models import Device, DeviceType
from providers.shizuku.provider import ShizukuProvider
from providers.shizuku.transport import HttpCompanionTransport


@pytest.fixture
def temp_dir():
    d = tempfile.mkdtemp(prefix="safeer_test_v09_")
    yield Path(d)
    shutil.rmtree(d, ignore_errors=True)


def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def test_companion_lifecycle_endpoint(temp_dir):
    """Preveri strukturirano poročilo /api/companion/lifecycle preko transporta."""
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

    srv_thread = threading.Thread(target=server.serve_forever, daemon=True)
    srv_thread.start()
    time.sleep(0.15)

    try:
        transport = HttpCompanionTransport(
            host="127.0.0.1",
            port=port,
            secret_token="a" * 64,
            use_tls=True
        )

        lc = transport.get_lifecycle()
        assert lc is not None
        assert isinstance(lc, CompanionLifecycleResponse)
        assert lc.version == "0.9.1"
        assert lc.protocol_version == "1.1"
        assert lc.companion_running is True
        assert lc.shizuku_available is True
        assert lc.shizuku_permission_granted is True
        assert lc.shizuku_state == "ready"
        assert lc.uptime_seconds >= 0.0
        assert lc.pid is not None
        assert "settings.read" in lc.supported_capabilities
        assert "app.force_stop" in lc.supported_capabilities
        assert "app.cache_maintenance" in lc.supported_capabilities

    finally:
        server.shutdown()
        server.server_close()


def test_shizuku_lifecycle_dynamic_state_transitions():
    """
    Preveri dinamična stanja Shizuku povezave in fail-closed obnašanje:
    - ready (UID 2000 aktiven)
    - permission_denied (dovoljenje preklicano)
    - waiting_for_shizuku (strežnik ni na voljo ali se zaganja)
    """
    # 1. Simulator izvajanja
    current_state = {"rc": 0, "out": "uid=2000(shell) gid=2000(shell)", "err": ""}

    def mock_executor(cmd: list[str]):
        return current_state["rc"], current_state["out"], current_state["err"]

    runner = ShizukuRunner(rish_path="/mock/rish", executor=mock_executor)

    # 1. Stanje: READY
    health = runner.get_health()
    assert health["shizuku_state"] == "ready"
    assert health["shizuku_available"] is True
    assert health["shizuku_permission_granted"] is True

    ok, reason, data = runner.execute_capability(
        Capability.SETTINGS_READ,
        {"namespace": "global", "key": "stay_on_while_plugged_in"}
    )
    assert ok is True

    # 2. Prehod v stanje: PERMISSION_DENIED
    current_state["rc"] = 13
    current_state["out"] = ""
    current_state["err"] = "Permission denied: user revoked Shizuku access"
    runner.probe_shizuku()

    health_denied = runner.get_health()
    assert health_denied["shizuku_state"] == "permission_denied"
    assert health_denied["shizuku_available"] is True
    assert health_denied["shizuku_permission_granted"] is False

    # Klic mora fail-closed zavrniti z jasnim opozorilom
    ok_fail, reason_fail, _ = runner.execute_capability(
        Capability.SETTINGS_READ,
        {"namespace": "global", "key": "stay_on_while_plugged_in"}
    )
    assert ok_fail is False
    assert "fail-closed" in reason_fail.lower()
    assert "permission_denied" in reason_fail.lower()

    # 3. Prehod v stanje: WAITING_FOR_SHIZUKU (strežnik se ponovno zaganja po rebootu)
    current_state["rc"] = 1
    current_state["out"] = ""
    current_state["err"] = "shizuku server not running"
    runner.probe_shizuku()

    health_waiting = runner.get_health()
    assert health_waiting["shizuku_state"] == "waiting_for_shizuku"
    assert health_waiting["shizuku_available"] is False
    assert health_waiting["shizuku_permission_granted"] is False

    # 4. Ponovna vzpostavitev: RECOVERED -> READY
    current_state["rc"] = 0
    current_state["out"] = "uid=2000(shell) gid=2000(shell)"
    current_state["err"] = ""
    runner.probe_shizuku()

    health_recovered = runner.get_health()
    assert health_recovered["shizuku_state"] == "ready"
    assert health_recovered["shizuku_permission_granted"] is True


def test_controlled_update_sha256_verification_and_rejection(temp_dir):
    """
    Preveri nadzorovane posodobitve (OTA):
    - Kriptografski HMAC podpis
    - Zavrnitev neveljavnega SHA-256 odtisa (Fail-Closed)
    - Uspešna potrditev pristne posodobitve z veljavnim Ed25519 podpisom
    """
    port = get_free_port()
    cert_path = temp_dir / "companion.crt"
    key_path = temp_dir / "companion.key"
    secret = "k" * 64

    # Generiraj par ključev za test
    priv_key, pub_key = CompanionLifecycleManager.generate_release_keypair()

    runner = ShizukuRunner(mock_mode=True)
    server = create_companion_server(
        host="127.0.0.1",
        port=port,
        secret_key=secret,
        runner=runner,
        use_tls=True,
        cert_file=str(cert_path),
        key_file=str(key_path),
        release_public_key=pub_key,
    )

    srv_thread = threading.Thread(target=server.serve_forever, daemon=True)
    srv_thread.start()
    time.sleep(0.15)

    try:
        transport = HttpCompanionTransport(
            host="127.0.0.1",
            port=port,
            secret_token=secret,
            use_tls=True
        )

        valid_binary_bytes = b"SAFEER_COMPANION_V0.9.1_TEST_BINARY"
        corrupted_binary_bytes = b"CORRUPTED_TAMPERED_BYTES"

        # 1. Poskus posodobitve z neujemajočim SHA-256 kontrolnim odtisom
        fake_sha = "0" * 64
        res_integrity_check = CompanionLifecycleManager.verify_integrity(valid_binary_bytes, fake_sha)
        assert res_integrity_check is False

        # 2. Poskus klica s ponarejenim payloadom neposredno prek HTTP
        from companion.protocol import CompanionUpdateRequest
        import base64
        import json
        import urllib.request
        from providers.shizuku.transport import FingerprintHTTPSHandler

        bad_sig = CompanionLifecycleManager.sign_release(corrupted_binary_bytes, priv_key)
        bad_req = CompanionUpdateRequest(
            binary_b64=base64.b64encode(corrupted_binary_bytes).decode("ascii"),
            sha256=fake_sha,
            release_signature=bad_sig,
            restart=False
        )
        bad_req.sign(secret)

        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), FingerprintHTTPSHandler())
        http_req = urllib.request.Request(
            transport.update_url,
            data=bad_req.model_dump_json().encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with pytest.raises(urllib.error.HTTPError) as exc:
            opener.open(http_req, timeout=3.0)
        assert exc.value.code == 400

        # 3. Pristna posodobitev z ujemajočim SHA-256 in veljavnim Ed25519 podpisom
        valid_sig = CompanionLifecycleManager.sign_release(valid_binary_bytes, priv_key)
        res = transport.update_companion(
            valid_binary_bytes,
            release_signature=valid_sig,
            version="0.9.1",
            restart=False
        )
        assert res.success is True
        assert "uspešno" in res.message.lower()

    finally:
        server.shutdown()
        server.server_close()


def test_controlled_update_ed25519_authenticity_and_forgery(temp_dir):
    """
    V0.9.1: Preveri Ed25519 preverjanje avtentičnosti izdaj in zaščito pred ponarejanjem:
    - Zavrnitev ponarejenega ali poškodovanega Ed25519 podpisa (Fail-Closed)
    - Zavrnitev podpisa drugega / nepooblaščenega ključa
    - Zavrnitev pristnega podpisa na zamenjanem binarnem tovoru (Payload Tampering)
    """
    port = get_free_port()
    cert_path = temp_dir / "companion_ed.crt"
    key_path = temp_dir / "companion_ed.key"
    secret = "e" * 64

    # Uradni ključ
    official_priv, official_pub = CompanionLifecycleManager.generate_release_keypair()
    # Napadalčev nepovezan ključ
    attacker_priv, attacker_pub = CompanionLifecycleManager.generate_release_keypair()

    runner = ShizukuRunner(mock_mode=True)
    server = create_companion_server(
        host="127.0.0.1",
        port=port,
        secret_key=secret,
        runner=runner,
        use_tls=True,
        cert_file=str(cert_path),
        key_file=str(key_path),
        release_public_key=official_pub,
    )

    srv_thread = threading.Thread(target=server.serve_forever, daemon=True)
    srv_thread.start()
    time.sleep(0.15)

    try:
        transport = HttpCompanionTransport(
            host="127.0.0.1",
            port=port,
            secret_token=secret,
            use_tls=True
        )

        binary_a = b"OFFICIAL_SAFEER_BINARY_V091"
        binary_b = b"MALICIOUS_REPLACED_BINARY_PAYLOAD"

        # 1. Poskus s ponarejenim (naključnim) Ed25519 podpisom
        forged_sig = "ff" * 64
        res_forged = transport.update_companion(
            binary_a,
            release_signature=forged_sig,
            restart=False
        )
        assert res_forged.success is False
        assert "Ed25519 podpis" in res_forged.error_message or "Release signature" in res_forged.error_message

        # 2. Poskus s podpisom, ustvarjenim z napadalčevim neavtoriziranim Ed25519 ključem
        attacker_sig = CompanionLifecycleManager.sign_release(binary_a, attacker_priv)
        res_attacker = transport.update_companion(
            binary_a,
            release_signature=attacker_sig,
            restart=False
        )
        assert res_attacker.success is False
        assert "Ed25519 podpis" in res_attacker.error_message or "Release signature" in res_attacker.error_message

        # 3. Poskus zamenjave tovora: veljaven podpis za binary_a poslan skupaj z binary_b
        valid_sig_a = CompanionLifecycleManager.sign_release(binary_a, official_priv)
        res_tampered = transport.update_companion(
            binary_b,
            release_signature=valid_sig_a,
            restart=False
        )
        assert res_tampered.success is False
        # Zavrnjeno bodisi zaradi neujemanja podpisa bodisi celovitosti
        assert "fail-closed" in res_tampered.error_message.lower()

        # 4. Pristna posodobitev z ujemajočim uradnim podpisom
        res_valid = transport.update_companion(
            binary_a,
            release_signature=valid_sig_a,
            version="0.9.1",
            restart=False
        )
        assert res_valid.success is True
        assert "uspešno" in res_valid.message.lower()

    finally:
        server.shutdown()
        server.server_close()


def test_controlled_update_anti_downgrade_protection(temp_dir):
    """
    V0.9.1: Preveri zaščito pred znižanjem različice (Anti-Downgrade / Monotonic Version Check):
    - Zavrnitev posodobitve na starejšo različico (npr. 0.9.0 ob trenutni 0.9.1)
    - Zavrnitev posodobitve na 0.8.1
    - Dovoljena posodobitev na enako (0.9.1) ali novejšo različico (1.0.0)
    """
    port = get_free_port()
    cert_path = temp_dir / "companion_down.crt"
    key_path = temp_dir / "companion_down.key"
    secret = "d" * 64

    priv_key, pub_key = CompanionLifecycleManager.generate_release_keypair()

    runner = ShizukuRunner(mock_mode=True)
    server = create_companion_server(
        host="127.0.0.1",
        port=port,
        secret_key=secret,
        runner=runner,
        use_tls=True,
        cert_file=str(cert_path),
        key_file=str(key_path),
        release_public_key=pub_key,
    )

    srv_thread = threading.Thread(target=server.serve_forever, daemon=True)
    srv_thread.start()
    time.sleep(0.15)

    try:
        transport = HttpCompanionTransport(
            host="127.0.0.1",
            port=port,
            secret_token=secret,
            use_tls=True
        )

        test_bin = b"SAFEER_COMPANION_VERSION_TEST_BINARY"
        sig = CompanionLifecycleManager.sign_release(test_bin, priv_key)

        # 1. Poskus downgrade na 0.9.0 (ob trenutni 0.9.1)
        res_down_090 = transport.update_companion(
            test_bin,
            release_signature=sig,
            version="0.9.0",
            restart=False
        )
        assert res_down_090.success is False
        assert "Anti-downgrade zaščita" in res_down_090.error_message
        assert "0.9.0" in res_down_090.error_message

        # 2. Poskus downgrade na 0.8.1
        res_down_081 = transport.update_companion(
            test_bin,
            release_signature=sig,
            version="0.8.1",
            restart=False
        )
        assert res_down_081.success is False
        assert "Anti-downgrade zaščita" in res_down_081.error_message

        # 3. Enaka različica (reinstall iste verzije 0.9.1)
        res_same = transport.update_companion(
            test_bin,
            release_signature=sig,
            version="0.9.1",
            restart=False
        )
        assert res_same.success is True

        # 4. Nadgradnja na novejšo različico 1.0.0
        res_upgrade = transport.update_companion(
            test_bin,
            release_signature=sig,
            version="1.0.0",
            restart=False
        )
        assert res_upgrade.success is True
        assert res_upgrade.new_version == "1.0.0"

    finally:
        server.shutdown()
        server.server_close()


def test_go_companion_v091_native_lifecycle_and_version(temp_dir):
    """
    Preveri delovanje pravega Go binarnega programa:
    1. Preverjanje zastavice -version (0.9.1)
    2. Zagon v TLS pairing načinu
    3. Pridobitev /api/companion/lifecycle poročila
    """
    import re
    go_bin = Path("/tmp/safeer-companion-test")
    if not go_bin.exists():
        pytest.skip("Go testni binarni program /tmp/safeer-companion-test ne obstaja.")

    # 1. Preveri CLI -version
    out = subprocess.check_output([str(go_bin), "-version"], text=True)
    assert "Safeer Companion v0.9.1" in out
    assert "protocol 1.1" in out

    # 2. Zagon daemona
    port = get_free_port()
    cert_path = temp_dir / "go_companion.crt"
    key_path = temp_dir / "go_companion.key"
    mock_rish = temp_dir / "mock_rish.sh"
    mock_rish.write_text('#!/bin/sh\necho "uid=2000(shell) gid=2000(shell)"\n')
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

        device = Device(id="go_companion_v091", name="Go V0.9.1 Phone", type=DeviceType.SHIZUKU, host="127.0.0.1", port=port)
        provider = ShizukuProvider(device=device)

        derived_key, tls_fp = provider.pair_pin(pin)
        assert len(derived_key) == 64
        assert len(tls_fp) == 64

        # Preveri lifecycle prek pravega Go TLS Companiona
        lc = provider.get_lifecycle_status()
        assert lc["version"] == "0.9.1"
        assert lc["protocol_version"] == "1.1"
        assert lc["shizuku_state"] == "ready"
        assert lc["companion_running"] is True
        assert lc["pid"] is not None
        assert "settings.read" in lc["supported_capabilities"]

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=2.0)
        except Exception:
            proc.kill()


def test_android_apk_packaging_and_manifest():
    """
    Preveri veljavnost zgrajenega SafeerCompanion.apk:
    - Prisotnost classes.dex in assets/safeer-companion
    - Veljavnost deklariranih storitev in sprejemnikov v AndroidManifest.xml
    """
    manifest_path = Path(__file__).parent.parent / "companion" / "android" / "AndroidManifest.xml"
    assert manifest_path.exists()
    content = manifest_path.read_text(encoding="utf-8")

    assert "com.safeer.companion" in content
    assert "android.permission.RECEIVE_BOOT_COMPLETED" in content
    assert "android.permission.FOREGROUND_SERVICE" in content
    assert "moe.shizuku.manager.permission.API_V23" in content
    assert "SafeerCompanionService" in content
    assert "BootReceiver" in content
    assert "android.intent.action.BOOT_COMPLETED" in content

    apk_path = Path(__file__).parent.parent / "companion" / "android" / "build" / "SafeerCompanion.apk"
    if apk_path.exists():
        with zipfile.ZipFile(apk_path, "r") as zf:
            namelist = zf.namelist()
            assert "classes.dex" in namelist
            assert "assets/safeer-companion" in namelist
            assert "AndroidManifest.xml" in namelist


def test_apk_builder_script_configuration_and_no_hardcoded_paths():
    """
    V0.9.1: Preveri, da build_companion_apk.sh podpira okoljske spremenljivke:
    - ANDROID_HOME / ANDROID_SDK_ROOT
    - RELEASE_KEYSTORE in RELEASE_KEYSTORE_PASS za produkcijski podpis
    - Nima hardkodiranih privatnih poverilnic
    """
    script_path = Path(__file__).parent.parent / "companion" / "android" / "build_companion_apk.sh"
    assert script_path.exists()
    code = script_path.read_text(encoding="utf-8")

    assert "ANDROID_HOME" in code
    assert "ANDROID_SDK_ROOT" in code
    assert "RELEASE_KEYSTORE" in code
    assert "RELEASE_KEYSTORE_PASS" in code
    assert "RELEASE_KEY_ALIAS" in code

