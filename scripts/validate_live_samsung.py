#!/usr/bin/env python3
"""
Celovit avtomatiziran testni paket za verifikacijo na živi napravi (Samsung Galaxy S25).
Izvaja vseh 12 predpisanih korakov:
 1. Baseline & Shizuku/rish (UID 2000)
 2. Namestitev in zagon Companion V0.9.1
 3. V0.8.1 authenticated PIN bootstrap + mutual transcript confirmation + TLS certificate pinning
 4. Privilegirane zmogljivosti (settings.read, app.force_stop, app.cache_maintenance)
 5. Simulacija izgube Shizuku (Fail-Closed)
 6. Samodejno okrevanje po obnovi Shizuku
 7. Varnostni preizkus OTA: Ponarejen Ed25519 podpis
 8. Varnostni preizkus OTA: Manipuliran tovor (Payload Tampering)
 9. Varnostni preizkus OTA: Anti-Downgrade zaščita (v0.9.0 zavrnitev)
10. Pristna OTA posodobitev in neodvisna verifikacija on-disk SHA-256 zgoščevalne vrednosti
11. Nadzornik (Watchdog / Supervisor) in samodejni ponovni zagon ob prekinitvi
12. Neodvisen FPS Performance Observer na zaslonu Samsung S25
"""

import os
import sys
import time
import json
import re
import shutil
import hashlib
import subprocess
from typing import Dict, Any, List, Optional, Tuple

# Zagotovi dostop do modulov projekta
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.devices.models import Device, DeviceType
from core.security.keystore import get_keystore, DeviceKeyStore
from companion.lifecycle import CompanionLifecycleManager
from companion.protocol import Capability
from providers.shizuku.provider import ShizukuProvider
from providers.shizuku.transport import HttpCompanionTransport
from core.observers.fps_observer import FpsObserver


class LiveSamsungValidator:
    def __init__(self, adb_target: str, host_port: int = 8995):
        self.adb_target = adb_target.strip()
        self.host_port = host_port
        self.local_url = f"127.0.0.1:{host_port}"
        self.results: List[Dict[str, Any]] = []
        self.release_priv: Optional[str] = None
        self.release_pub: Optional[str] = None
        self.paired_key: Optional[str] = None
        self.pinned_fp: Optional[str] = None
        self.keystore = get_keystore()
        self.device = Device(
            id="samsung_s25_live",
            name="Samsung Galaxy S25 (SM-S931B)",
            type=DeviceType.SHIZUKU,
            host="127.0.0.1",
            port=self.host_port,
        )

    def log(self, section: str, message: str):
        print(f"\n[{section}] {message}")

    def run_adb(self, args: List[str], timeout: float = 10.0) -> Tuple[int, str, str]:
        cmd = ["adb", "-s", self.adb_target] + args
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return res.returncode, res.stdout.strip(), res.stderr.strip()
        except subprocess.TimeoutExpired:
            return 124, "", "Timeout"
        except Exception as e:
            return 1, "", str(e)

    def record_result(self, step_num: int, name: str, expected: str, actual: str, passed: bool, notes: str = ""):
        status = "PASS" if passed else "FAIL"
        symbol = "✅" if passed else "❌"
        print(f"  {symbol} Korak {step_num}: {name} -> {status}")
        print(f"     Pričakovano: {expected}")
        print(f"     Dejansko:    {actual}")
        if notes:
            print(f"     Opomba:      {notes}")
        self.results.append({
            "step": step_num,
            "name": name,
            "expected": expected,
            "actual": actual,
            "status": status,
            "notes": notes
        })

    def step_01_baseline_shizuku_rish(self) -> bool:
        self.log("KORAK 1/12", "Preverjanje osnovnega stanja naprave, ADB in Shizuku rish (UID 2000)")
        rc, out, err = self.run_adb(["shell", "/data/local/tmp/rish", "-c", "id"])
        combined = (out + " " + err).strip()
        expected = "uid=2000(shell) z ustreznimi pravicami"
        actual = combined if ("uid=2000" in combined) else f"RC={rc}, out={out}, err={err}"
        passed = ("uid=2000" in combined)
        self.record_result(1, "Baseline & Shizuku/rish", expected, actual, passed)
        return passed

    def step_02_deploy_companion_binary(self) -> bool:
        self.log("KORAK 2/12", "Priprava in namestitev Safeer Companion V0.9.1 ARM64 binarne datoteke")
        
        # 1. Generiraj nov Ed25519 par ključev za verifikacijo te seje
        self.release_priv, self.release_pub = CompanionLifecycleManager.generate_release_keypair()
        
        # 2. Prevedi ARM64 Go companion binarno datoteko
        bin_path = "/tmp/safeer-companion"
        build_cmd = [
            "go", "build", "-ldflags=-s -w", "-o", bin_path,
            os.path.join(PROJECT_ROOT, "companion", "native", "main.go")
        ]
        env = os.environ.copy()
        env["GOOS"] = "linux"
        env["GOARCH"] = "arm64"
        env["CGO_ENABLED"] = "0"
        env["GOCACHE"] = "/tmp/gocache"
        
        res = subprocess.run(build_cmd, env=env, capture_output=True, text=True)
        if res.returncode != 0:
            self.record_result(2, "Gradnja ARM64 Go binarnega programa", "Uspešen prevod", f"Go build failed: {res.stderr}", False)
            return False

        # 3. Ustavi obstoječe procese na napravi
        self.run_adb(["shell", "pkill -f safeer-companion || true"])
        time.sleep(0.5)

        # 4. Prenesi na napravo in nastavi 0700
        rc_push, out_push, err_push = self.run_adb(["push", bin_path, "/data/local/tmp/safeer-companion"])
        rc_chmod, out_chmod, _ = self.run_adb(["shell", "chmod 0700 /data/local/tmp/safeer-companion"])
        
        # 5. Preveri verzijo
        rc_ver, out_ver, _ = self.run_adb(["shell", "/data/local/tmp/safeer-companion -version"])
        
        expected = "Safeer Companion v0.9.1 (protocol 1.1) z dovoljenji 0700"
        actual = f"{out_ver} (chmod rc={rc_chmod})"
        passed = (rc_ver == 0 and "v0.9.1" in out_ver and "1.1" in out_ver)
        self.record_result(2, "Namestitev Companion V0.9.1", expected, actual, passed)
        return passed

    def step_03_pairing_bootstrap_and_tls_pinning(self) -> bool:
        self.log("KORAK 3/12", "V0.8.1 authenticated PIN bootstrap + mutual transcript confirmation + TLS certificate pinning")
        
        # Počisti pretekle dnevnike in zaženi demon z generiranjem PIN-a in določenim Ed25519 javnim ključem
        self.run_adb(["shell", "rm -f /data/local/tmp/safeer-companion.log /data/local/tmp/companion.crt /data/local/tmp/companion.key"])
        
        launch_cmd = (
            f"nohup /data/local/tmp/safeer-companion "
            f"-host=0.0.0.0 -port={self.host_port} -tls -pair "
            f"-rish-path=/data/local/tmp/rish "
            f"-release-pubkey={self.release_pub} "
            f"> /data/local/tmp/safeer-companion.log 2>&1 &"
        )
        self.run_adb(["shell", launch_cmd])
        time.sleep(1.2)

        # Preberi log in izlušči PIN ter začetni prstni odtis
        _, log_out, _ = self.run_adb(["shell", "cat /data/local/tmp/safeer-companion.log"])
        
        m_pin = re.search(r"PIN ZA SEZNANITEV:\s*(\d{6})", log_out)
        if not m_pin:
            self.record_result(3, "V0.8.1 PIN bootstrap", "Prejet 6-mestni PIN", f"Log ne vsebuje PIN-a: {log_out}", False)
            return False
            
        pin = m_pin.group(1)
        
        # Vzpostavi ADB port forwarding za zanesljivost
        subprocess.run(["adb", "-s", self.adb_target, "forward", f"tcp:{self.host_port}", f"tcp:{self.host_port}"], capture_output=True)

        # Izvedi avtenticiran bootstrap prek ShizukuProvider
        provider = ShizukuProvider(self.device, keystore=self.keystore)
        try:
            derived_key, tls_fp = provider.pair_pin(pin)
            self.paired_key = derived_key
            self.pinned_fp = tls_fp
            
            # Preveri zdravje in življenjski cikel
            health_ok = provider.transport.check_health()
            lc = provider.transport.get_lifecycle()
            
            expected = "derived_key >= 256-bit, pinned TLS SHA-256 fingerprint, health=True, shizuku_state='ready'"
            actual = f"KeyLen={len(derived_key)*4}b, FP={tls_fp[:16]}..., health={health_ok}, state={lc.shizuku_state if lc else None}"
            passed = bool(derived_key and len(derived_key) >= 64 and tls_fp and health_ok and lc and lc.shizuku_state == "ready")
            
            self.record_result(3, "V0.8.1 PIN bootstrap & TLS pinning", expected, actual, passed, f"PIN={pin}")
            return passed
        except Exception as e:
            self.record_result(3, "V0.8.1 PIN bootstrap & TLS pinning", "Uspešna vzpostavitev zaupanja", f"Izjema: {e}", False)
            return False

    def step_04_test_privileged_capabilities(self) -> bool:
        self.log("KORAK 4/12", "Preverjanje vseh 3 privilegiranih zmogljivosti skozi CapabilityGate #2")
        provider = ShizukuProvider(self.device, keystore=self.keystore)

        # 1. settings.read
        res_read = provider.read_setting("global", "stay_on_while_plugged_in")
        read_ok = (res_read.success and res_read.data and "value" in res_read.data)

        # 2. app.force_stop (dovoljen paket)
        pkg = "com.safeer.mobile.browser"
        res_stop = provider.force_stop(pkg)
        stop_ok = res_stop.success

        # 3. app.cache_maintenance (dovoljen paket)
        res_cache = provider.clear_cache(pkg)
        cache_ok = res_cache.success

        expected = "Vse 3 zmožnosti (settings.read, force_stop, clear_cache) vrnejo success=True"
        actual = f"settings.read={read_ok} (val={res_read.data.get('value') if res_read.data else None}), force_stop={stop_ok}, clear_cache={cache_ok}"
        passed = (read_ok and stop_ok and cache_ok)
        self.record_result(4, "Privilegirane zmogljivosti (Gate #2)", expected, actual, passed)
        return passed

    def step_05_shizuku_loss_fail_closed(self) -> bool:
        self.log("KORAK 5/12", "Simulacija izgube Shizuku (začasna preimenitev rish) -> Fail-Closed")
        
        # Preimenuj rish na napravi
        self.run_adb(["shell", "mv /data/local/tmp/rish /data/local/tmp/rish.hidden"])
        time.sleep(0.5)

        provider = ShizukuProvider(self.device, keystore=self.keystore)
        res = provider.read_setting("global", "stay_on_while_plugged_in")
        
        # Preveri, da demon ni padel, ampak je vrnil napako (Fail-Closed)
        rc_ps, out_ps, _ = self.run_adb(["shell", "pidof safeer-companion"])
        daemon_alive = (rc_ps == 0 and bool(out_ps.strip()))

        expected = "Zahteva zavrnjena (success=False, Fail-closed: Shizuku storitev ni na voljo), demon ostane aktiven"
        actual = f"success={res.success}, msg='{res.message}', daemon_alive={daemon_alive}"
        passed = (not res.success and ("Shizuku" in res.message or "Fail-closed" in res.message or "503" in res.message) and daemon_alive)
        self.record_result(5, "Shizuku izpad (Fail-Closed)", expected, actual, passed)
        return passed

    def step_06_shizuku_recovery(self) -> bool:
        self.log("KORAK 6/12", "Obnova Shizuku (povrnitev rish) -> samodejno okrevanje v 'ready'")
        
        # Obnovi rish
        self.run_adb(["shell", "mv /data/local/tmp/rish.hidden /data/local/tmp/rish"])
        time.sleep(0.5)

        provider = ShizukuProvider(self.device, keystore=self.keystore)
        lc = provider.transport.get_lifecycle()
        res = provider.read_setting("global", "stay_on_while_plugged_in")

        expected = "Avtomatsko okrevanje: lc.shizuku_state == 'ready', settings.read success=True"
        actual = f"shizuku_state='{lc.shizuku_state if lc else None}', settings.read success={res.success}"
        passed = bool(lc and lc.shizuku_state == "ready" and res.success)
        self.record_result(6, "Shizuku samodejno okrevanje", expected, actual, passed)
        return passed

    def step_07_ota_forged_signature_rejection(self) -> bool:
        self.log("KORAK 7/12", "Varnostni preizkus OTA: Poskus posodobitve s ponarejenim Ed25519 podpisom")
        provider = ShizukuProvider(self.device, keystore=self.keystore)

        payload_bytes = b"MOCK_MALICIOUS_PAYLOAD_SAFEER_OTA"
        forged_sig = "ff" * 64

        res = provider.transport.update_companion(
            binary_bytes=payload_bytes,
            release_signature=forged_sig,
            version="0.9.2",
            restart=False
        )

        expected = "HTTP 400 zavrnitev: Neveljaven Ed25519 podpis izdaje (Fail-Closed)"
        actual = f"success={res.success}, err='{res.error_message}'"
        passed = (not res.success and ("Ed25519" in res.error_message or "400" in res.error_message or "Release signature" in res.error_message))
        self.record_result(7, "OTA ponarejen Ed25519 podpis", expected, actual, passed)
        return passed

    def step_08_ota_tampered_payload_rejection(self) -> bool:
        self.log("KORAK 8/12", "Varnostni preizkus OTA: Podpis veljaven za binarni program A, a poslan manipuliran tovor B")
        provider = ShizukuProvider(self.device, keystore=self.keystore)

        binary_a = b"OFFICIAL_SAFEER_PAYLOAD_A"
        binary_b = b"MANIPULATED_INJECTED_PAYLOAD_B"

        # Ustvari veljaven podpis za tovor A z uradnim zasebnim ključem te seje
        valid_sig_a = CompanionLifecycleManager.sign_release(binary_a, self.release_priv)

        # Pošlji tovor B s podpisom od A
        res = provider.transport.update_companion(
            binary_bytes=binary_b,
            release_signature=valid_sig_a,
            version="0.9.2",
            restart=False
        )

        expected = "Zavrnitev (Fail-Closed): SHA-256 ali Ed25519 neskladje med tovorom in podpisom"
        actual = f"success={res.success}, err='{res.error_message}'"
        passed = (not res.success and ("Ed25519" in res.error_message or "SHA-256" in res.error_message or "400" in res.error_message))
        self.record_result(8, "OTA manipuliran tovor (Tampering)", expected, actual, passed)
        return passed

    def step_09_ota_anti_downgrade_rejection(self) -> bool:
        self.log("KORAK 9/12", "Varnostni preizkus OTA: Poskus znižanja verzije na 0.9.0 (Anti-Downgrade)")
        
        # Sestavi in prevedi ARM64 binarno datoteko z verzijo 0.9.0
        downgrade_src = "/tmp/safeer_v090_dummy.go"
        with open(downgrade_src, "w") as f:
            f.write("""package main
import "fmt"
func main() { fmt.Println("Safeer Companion v0.9.0 (protocol 1.1)") }
""")
        downgrade_bin = "/tmp/safeer-companion-v090"
        env = os.environ.copy()
        env["GOOS"] = "linux"
        env["GOARCH"] = "arm64"
        env["CGO_ENABLED"] = "0"
        subprocess.run(["go", "build", "-o", downgrade_bin, downgrade_src], env=env, check=True)

        with open(downgrade_bin, "rb") as f:
            downgrade_bytes = f.read()

        # Podpiši z uradnim Ed25519 ključem
        valid_sig_v090 = CompanionLifecycleManager.sign_release(downgrade_bytes, self.release_priv)

        provider = ShizukuProvider(self.device, keystore=self.keystore)
        res = provider.transport.update_companion(
            binary_bytes=downgrade_bytes,
            release_signature=valid_sig_v090,
            version="0.9.0",
            restart=False
        )

        expected = "Zavrnitev: Anti-downgrade zaščita! Nova različica (0.9.0) je nižja od trenutne (0.9.1)"
        actual = f"success={res.success}, err='{res.error_message}'"
        passed = (not res.success and ("Anti-downgrade" in res.error_message or "nižja" in res.error_message or "400" in res.error_message))
        self.record_result(9, "OTA anti-downgrade zaščita", expected, actual, passed)
        return passed

    def step_10_ota_valid_update_and_disk_hash_verification(self) -> bool:
        self.log("KORAK 10/12", "Pristna OTA posodobitev in neodvisna verifikacija on-disk SHA-256 zgoščevalne vrednosti")
        
        # Pripravi veljaven nadgrajen ARM64 binarni program (npr. z verzijo 0.9.1)
        with open("/tmp/safeer-companion", "rb") as f:
            valid_bytes = f.read()

        expected_sha256 = hashlib.sha256(valid_bytes).hexdigest().lower()
        valid_sig = CompanionLifecycleManager.sign_release(valid_bytes, self.release_priv)

        provider = ShizukuProvider(self.device, keystore=self.keystore)
        res = provider.transport.update_companion(
            binary_bytes=valid_bytes,
            release_signature=valid_sig,
            version="0.9.1",
            restart=False
        )

        update_ok = (res.success and "uspešno" in res.message.lower())

        # NEODVISNO PREVERJANJE NA DISKU TELEFONA
        rc_sha, out_sha, _ = self.run_adb(["shell", "sha256sum /data/local/tmp/safeer-companion"])
        on_disk_sha = out_sha.split()[0].lower() if rc_sha == 0 and out_sha else ""

        hash_matches = (on_disk_sha == expected_sha256)
        expected = f"OTA success=True IN dejanski on-disk sha256sum ({expected_sha256[:16]}...) se 100% ujema"
        actual = f"OTA success={update_ok}, on_disk_sha={on_disk_sha[:16]}..., match={hash_matches}"
        passed = (update_ok and hash_matches)
        self.record_result(10, "Pristna OTA in on-disk verifikacija", expected, actual, passed)
        return passed

    def step_11_supervisor_watchdog_recovery(self) -> bool:
        self.log("KORAK 11/12", "Preverjanje nadzornika safeer-companion-watchdog.sh (samodejni ponovni zagon ob prekinitvi)")
        
        # Pripravi in pošlji watchdog skript
        watchdog_path = os.path.join(PROJECT_ROOT, "companion", "scripts", "safeer-companion-watchdog.sh")
        self.run_adb(["push", watchdog_path, "/data/local/tmp/safeer-companion-watchdog.sh"])
        self.run_adb(["shell", "chmod 0700 /data/local/tmp/safeer-companion-watchdog.sh"])

        # Shranimo trenutni ključ v datoteko /data/local/tmp/companion.key z 0600
        self.run_adb(["shell", f"echo -n '{self.paired_key}' > /data/local/tmp/companion.key && chmod 0600 /data/local/tmp/companion.key"])

        # Zaustavi obstoječe demone
        self.run_adb(["shell", "pkill -f safeer-companion || true"])
        time.sleep(0.5)

        # Zaženi watchdog v ozadju
        self.run_adb(["shell", "nohup /data/local/tmp/safeer-companion-watchdog.sh > /data/local/tmp/watchdog_exec.log 2>&1 &"])
        time.sleep(2.0)

        # Pridobi PID začetnega procesa
        _, pid1, _ = self.run_adb(["shell", "pidof safeer-companion"])
        pid1 = pid1.strip()
        if not pid1:
            self.record_result(11, "Watchdog nadzornik", "Companion teče pod nadzornikom", "safeer-companion ni zagnan", False)
            return False

        # Prekini proces (kill -9)
        self.run_adb(["shell", f"kill -9 {pid1}"])
        time.sleep(2.5)

        # Preveri, ali ga je watchdog samodejno ponovno zagnal (novi PID)
        _, pid2, _ = self.run_adb(["shell", "pidof safeer-companion"])
        pid2 = pid2.strip()
        respawned = bool(pid2 and pid2 != pid1)

        expected = "Po zrušitvi (kill -9) watchdog samodejno zažene nov proces (nov PID)"
        actual = f"Začetni PID={pid1}, Novi PID po zrušitvi={pid2}, Okrevanje={respawned}"
        passed = respawned
        self.record_result(11, "Nadzornik & okrevanje procesa", expected, actual, passed)
        return passed

    def step_12_fps_performance_benchmark(self) -> bool:
        self.log("KORAK 12/12", "Neodvisen FPS Performance Observer (Meritve hitrosti osveževanja in zakasnitev na Samsung S25)")
        
        observer = FpsObserver(adb_target=self.adb_target)
        # Samodejno zaznaj trenutno aktivni paket na zaslonu (read-only opazovanje)
        res = observer.measure(package_name=None, duration_seconds=2.0)
        
        expected = "Metrike pridobljene: observed_fps, frame_time_ms (avg, p50, p95), jank_percent, measurement_source != 'none'"
        if res.get("success"):
            fps = res.get("observed_fps")
            hz = res.get("refresh_rate_hz")
            ft = res.get("frame_time_ms", {})
            jank = res.get("jank_percent")
            src = res.get("measurement_source")
            actual = f"FPS={fps}, Zaslon={hz}Hz, p95={ft.get('p95')}ms, Jank={jank}%, Vir={src}"
            passed = True
        else:
            actual = f"Meritev ni uspela: {res.get('error')}"
            passed = False

        self.record_result(12, "FPS Performance Observer (Read-Only)", expected, actual, passed)
        return passed

    def run_all(self):
        print("=" * 80)
        print("🚀 ZAČETEK E2E VALIDACIJE NA ŽIVI NAPRAVI SAMSUNG GALAXY S25 (SM-S931B)")
        print(f"   • Ciljna ADB naprava:  {self.adb_target}")
        print(f"   • Gostiteljska vrata: {self.host_port}")
        print("=" * 80)

        t0 = time.time()
        self.step_01_baseline_shizuku_rish()
        self.step_02_deploy_companion_binary()
        self.step_03_pairing_bootstrap_and_tls_pinning()
        self.step_04_test_privileged_capabilities()
        self.step_05_shizuku_loss_fail_closed()
        self.step_06_shizuku_recovery()
        self.step_07_ota_forged_signature_rejection()
        self.step_08_ota_tampered_payload_rejection()
        self.step_09_ota_anti_downgrade_rejection()
        self.step_10_ota_valid_update_and_disk_hash_verification()
        self.step_11_supervisor_watchdog_recovery()
        self.step_12_fps_performance_benchmark()
        elapsed = round(time.time() - t0, 2)

        print("\n" + "=" * 80)
        print(f"📋 KONČNO DOKAZNO POROČILO VALIDACIJE ({elapsed}s)")
        print("=" * 80)
        print(f"{'ŠT':<4} | {'TEST / FUNKCIONALNOST':<35} | {'STATUS':<8} | {'REZULTAT'}")
        print("-" * 80)
        all_passed = True
        for r in self.results:
            status_str = f"✅ PASS" if r["status"] == "PASS" else "❌ FAIL"
            if r["status"] != "PASS":
                all_passed = False
            short_act = (r["actual"][:35] + "...") if len(r["actual"]) > 35 else r["actual"]
            print(f"{r['step']:<4} | {r['name']:<35} | {status_str:<8} | {short_act}")

        print("=" * 80)
        if all_passed:
            print("🏆 VSIH 12 KORAKOV USPEŠNO OPRAVLJENIH (12/12 PASS) NA SAMSUNG GALAXY S25!")
        else:
            print("⚠️ NEKATERI KORAKI NISO BILI OPRAVLJENI Z OCENO PASS.")
        print("=" * 80)
        return all_passed


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("ADB_TARGET", "").strip()
    if not target:
        res = subprocess.run(["adb", "devices"], capture_output=True, text=True)
        lines = [l.split()[0] for l in res.stdout.strip().splitlines()[1:] if l.strip() and "\tdevice" in l]
        if lines:
            target = lines[0]

    if not target:
        print("NAPAKA: Nobena ADB naprava ni določena.")
        print("Uporaba: python3 scripts/validate_live_samsung.py <serial|ip:port>")
        print("Ali nastavite spremenljivko okolja: export ADB_TARGET=<serial|ip:port>")
        sys.exit(1)

    validator = LiveSamsungValidator(adb_target=target)
    success = validator.run_all()
    sys.exit(0 if success else 1)
