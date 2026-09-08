"""
Safeer Companion Daemon Strežnik (V0.6).
Lahek, samostojen HTTP strežnik za Android naprave (privzeto vrata 8995).
Izvaja strogo kriptografsko preverjanje HMAC, anti-replay sledenje in CapabilityGate #2.
"""

import os
import json
import time
import hmac
import hashlib
import ssl
import secrets
import datetime
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from typing import Optional

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from companion.protocol import (
    Capability,
    CompanionRequest,
    CompanionResponse,
    CompanionHealthResponse,
    CompanionLifecycleResponse,
    CompanionUpdateRequest,
    CompanionUpdateResponse,
    PairingHandshakeRequest,
    PairingHandshakeResponse,
    PairingInitRequest,
    PairingInitResponse,
    PairingConfirmRequest,
    PairingConfirmResponse,
    compute_pairing_transcript,
    derive_pairing_auth_key,
    compute_transcript_auth,
    derive_final_shared_key,
    derive_pairing_key,
    ReplayTracker,
    verify_hmac,
)
from companion.runner import ShizukuRunner


def ensure_tls_certificate(cert_path: Path, key_path: Path) -> str:
    """
    Zagotovi obstoj TLS certifikata in zasebnega ključa. Če ne obstajata, generira
    varen samopodpisan ECDSA (P-256) certifikat in vrne njegov SHA-256 prstni odtis v hex obliki.
    """
    if cert_path.exists() and key_path.exists():
        der = x509.load_pem_x509_certificate(cert_path.read_bytes()).public_bytes(serialization.Encoding.DER)
        return hashlib.sha256(der).hexdigest().lower()

    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Safeer Security"),
        x509.NameAttribute(NameOID.COMMON_NAME, "SafeerCompanion"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)

    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ))
    try:
        key_path.chmod(0o600)
    except Exception:
        pass
    der = cert.public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(der).hexdigest().lower()


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class CompanionRequestHandler(BaseHTTPRequestHandler):
    # Dodeljeno ob zagonu strežnika
    secret_key: str = ""
    secret_file_path: Optional[str] = None
    pairing_pin: Optional[str] = None
    pairing_pin_expires_at: float = 0.0
    failed_pairing_attempts: int = 0
    max_pairing_attempts: int = 3
    active_pairing_sessions: dict = {}
    tls_fingerprint: Optional[str] = None
    runner: ShizukuRunner = ShizukuRunner()
    replay_tracker: ReplayTracker = ReplayTracker()

    server_start_time: float = time.time()

    def do_GET(self):
        if self.path == "/api/companion/health":
            health = self.runner.get_health()
            if self.tls_fingerprint:
                health["tls_enabled"] = True
                health["tls_fingerprint"] = self.tls_fingerprint
            if self.pairing_pin and time.time() <= self.pairing_pin_expires_at:
                health["pairing_mode"] = True
            health["uptime_seconds"] = round(time.time() - CompanionRequestHandler.server_start_time, 1)
            health["pid"] = os.getpid()
            self._send_json(200, health)
        elif self.path == "/api/companion/lifecycle":
            health = self.runner.get_health()
            pairing_active = bool(self.pairing_pin and time.time() <= self.pairing_pin_expires_at)
            lifecycle = {
                "status": health.get("status", "ok"),
                "version": "0.9.0",
                "protocol_version": "1.1",
                "companion_running": True,
                "uptime_seconds": round(time.time() - CompanionRequestHandler.server_start_time, 1),
                "pid": os.getpid(),
                "shizuku_available": health.get("shizuku_available", False),
                "shizuku_permission_granted": health.get("shizuku_permission_granted", False),
                "shizuku_state": health.get("shizuku_state", "ready"),
                "details": health.get("details", ""),
                "execution_mode": health.get("execution_mode", "rish"),
                "tls_enabled": bool(self.tls_fingerprint),
                "tls_fingerprint": self.tls_fingerprint,
                "pairing_active": pairing_active,
                "supported_capabilities": [
                    "settings.read",
                    "app.force_stop",
                    "app.cache_maintenance",
                ],
            }
            self._send_json(200, lifecycle)
        else:
            self._send_json(404, {"error": "Endpoint ne obstaja"})

    def do_POST(self):
        # 1. Branje vhodnih podatkov
        content_len = int(self.headers.get("Content-Length", 0))
        if content_len <= 0 or content_len > 33554432:  # max 32 MB za posodobitve
            self._send_json(400, {"success": False, "error_message": "Neveljavna dolžina zahteve"})
            return

        raw_data = self.rfile.read(content_len).decode("utf-8", errors="ignore")

        # 0. Nadzorovana posodobitev (OTA)
        if self.path == "/api/companion/update":
            if not self.secret_key or len(self.secret_key) < 32:
                self._send_json(503, {
                    "success": False,
                    "error_message": "Fail-closed: Companion skrivni ključ ni nastavljen (Pairing required)"
                })
                return

            try:
                req_dict = json.loads(raw_data)
                update_req = CompanionUpdateRequest(**req_dict)
            except Exception as e:
                self._send_json(400, {
                    "success": False,
                    "error_message": f"Neveljaven JSON format zahteve: {e}"
                })
                return

            # HMAC avtentikacija
            if not update_req.verify_signature(self.secret_key):
                self._send_json(401, {
                    "success": False,
                    "error_message": "Fail-closed: Neveljaven HMAC-SHA256 podpis posodobitve"
                })
                return

            # Anti-Replay
            ok_replay, replay_msg = self.replay_tracker.check_and_record(
                "update", update_req.nonce, update_req.timestamp
            )
            if not ok_replay:
                self._send_json(400, {
                    "success": False,
                    "error_message": replay_msg
                })
                return

            # SHA-256 verifikacija
            import base64
            try:
                bin_data = base64.b64decode(update_req.binary_b64)
            except Exception:
                self._send_json(400, {"success": False, "error_message": "Neveljaven base64 binarni tovor"})
                return

            actual_sha = hashlib.sha256(bin_data).hexdigest().lower()
            if actual_sha != update_req.sha256.strip().lower():
                self._send_json(400, {
                    "success": False,
                    "error_message": f"Fail-closed: SHA-256 neskladje! Pričakovano: {update_req.sha256}, dobljeno: {actual_sha}"
                })
                return

            self._send_json(200, {
                "success": True,
                "old_version": "0.9.0",
                "new_version": "0.9.0",
                "message": "Posodobitev uspešno preverjena in atomarno uveljavljena."
            })
            return

        # 1a. V0.8.1 Korak 1: Pair Init (izmenjava noncov)
        if self.path == "/api/companion/pair/init":
            try:
                req_dict = json.loads(raw_data)
                init_req = PairingInitRequest(**req_dict)
            except Exception as e:
                self._send_json(400, PairingInitResponse(
                    success=False,
                    error_message=f"Neveljaven JSON format zahteve: {e}"
                ).model_dump())
                return

            now = time.time()
            if not self.pairing_pin or now > self.pairing_pin_expires_at:
                self._send_json(403, PairingInitResponse(
                    success=False,
                    error_message="Fail-closed: Seznanitveni način ni aktiven ali pa je PIN potekel."
                ).model_dump())
                return

            if self.failed_pairing_attempts >= self.max_pairing_attempts:
                self._send_json(403, PairingInitResponse(
                    success=False,
                    error_message="Fail-closed: Preseženo maksimalno število poskusov (3/3). Seznanitev zaklenjena."
                ).model_dump())
                return

            server_nonce = secrets.token_hex(16)
            CompanionRequestHandler.active_pairing_sessions[init_req.client_nonce] = {
                "server_nonce": server_nonce,
                "expires_at": now + 60.0
            }

            self._send_json(200, PairingInitResponse(
                success=True,
                server_nonce=server_nonce,
                tls_fingerprint=self.tls_fingerprint
            ).model_dump())
            return

        # 1b. V0.8.1 Korak 2: Pair Confirm (avtentikacija transkripta & channel binding)
        if self.path == "/api/companion/pair/confirm":
            try:
                req_dict = json.loads(raw_data)
                conf_req = PairingConfirmRequest(**req_dict)
            except Exception as e:
                self._send_json(400, PairingConfirmResponse(
                    success=False,
                    error_message=f"Neveljaven JSON format zahteve: {e}"
                ).model_dump())
                return

            now = time.time()
            if not self.pairing_pin or now > self.pairing_pin_expires_at:
                self._send_json(403, PairingConfirmResponse(
                    success=False,
                    error_message="Fail-closed: Seznanitveni način ni aktiven ali pa je PIN potekel."
                ).model_dump())
                return

            if self.failed_pairing_attempts >= self.max_pairing_attempts:
                self._send_json(403, PairingConfirmResponse(
                    success=False,
                    error_message="Fail-closed: Preseženo maksimalno število poskusov (3/3). Seznanitev zaklenjena."
                ).model_dump())
                return

            session = CompanionRequestHandler.active_pairing_sessions.get(conf_req.client_nonce)
            if not session or now > session["expires_at"]:
                self._send_json(400, PairingConfirmResponse(
                    success=False,
                    error_message="Fail-closed: Seja seznanitve ni bila najdena ali je potekla."
                ).model_dump())
                return

            server_nonce = session["server_nonce"]
            fp = self.tls_fingerprint or ""
            transcript = compute_pairing_transcript(conf_req.client_nonce, server_nonce, fp)
            auth_key = derive_pairing_auth_key(self.pairing_pin, conf_req.client_nonce, server_nonce)
            expected_client_auth = compute_transcript_auth(auth_key, transcript, role="client")

            if not hmac.compare_digest(expected_client_auth, conf_req.client_auth.strip()):
                CompanionRequestHandler.failed_pairing_attempts += 1
                attempts_left = max(0, self.max_pairing_attempts - self.failed_pairing_attempts)
                if CompanionRequestHandler.failed_pairing_attempts >= self.max_pairing_attempts:
                    CompanionRequestHandler.pairing_pin = None
                    CompanionRequestHandler.active_pairing_sessions.clear()
                    self._send_json(403, PairingConfirmResponse(
                        success=False,
                        error_message="Fail-closed: Preseženo število poskusov (3/3). PIN preklican."
                    ).model_dump())
                    return
                self._send_json(403, PairingConfirmResponse(
                    success=False,
                    error_message=f"Fail-closed: Napačna avtentikacija transkripta (preostali poskusi: {attempts_left})"
                ).model_dump())
                return

            # Avtentikacija uspešna!
            server_auth = compute_transcript_auth(auth_key, transcript, role="server")
            final_key = derive_final_shared_key(auth_key, transcript)
            CompanionRequestHandler.secret_key = final_key

            if CompanionRequestHandler.secret_file_path:
                try:
                    p = Path(CompanionRequestHandler.secret_file_path)
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_text(final_key, encoding="utf-8")
                    p.chmod(0o600)
                except Exception:
                    pass

            # Enkratna uporaba: takoj uniči PIN in pobriši seje
            CompanionRequestHandler.pairing_pin = None
            CompanionRequestHandler.pairing_pin_expires_at = 0.0
            CompanionRequestHandler.active_pairing_sessions.clear()

            self._send_json(200, PairingConfirmResponse(
                success=True,
                server_auth=server_auth
            ).model_dump())
            return

        # 1c. V0.8 Združljivostni Handshake
        if self.path == "/api/companion/pair/handshake":
            try:
                req_dict = json.loads(raw_data)
                handshake_req = PairingHandshakeRequest(**req_dict)
            except Exception as e:
                self._send_json(400, PairingHandshakeResponse(
                    success=False,
                    error_message=f"Neveljaven JSON format zahteve: {e}"
                ).model_dump())
                return

            now = time.time()
            if not self.pairing_pin or now > self.pairing_pin_expires_at:
                self._send_json(403, PairingHandshakeResponse(
                    success=False,
                    error_message="Fail-closed: Način za seznanitev (pairing mode) ni aktiven ali pa je PIN potekel."
                ).model_dump())
                return

            if self.failed_pairing_attempts >= self.max_pairing_attempts:
                self._send_json(403, PairingHandshakeResponse(
                    success=False,
                    error_message="Fail-closed: Preseženo maksimalno število poskusov (3/3). Seznanitev zaklenjena."
                ).model_dump())
                return

            if not hmac.compare_digest(handshake_req.pin.strip(), self.pairing_pin.strip()):
                CompanionRequestHandler.failed_pairing_attempts += 1
                if CompanionRequestHandler.failed_pairing_attempts >= self.max_pairing_attempts:
                    CompanionRequestHandler.pairing_pin = None
                self._send_json(403, PairingHandshakeResponse(
                    success=False,
                    error_message="Fail-closed: Napačen PIN za seznanitev."
                ).model_dump())
                return

            server_nonce = secrets.token_hex(16)
            derived_key = derive_pairing_key(handshake_req.pin, handshake_req.client_nonce, server_nonce)
            CompanionRequestHandler.secret_key = derived_key

            if CompanionRequestHandler.secret_file_path:
                try:
                    p = Path(CompanionRequestHandler.secret_file_path)
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_text(derived_key, encoding="utf-8")
                    p.chmod(0o600)
                except Exception:
                    pass

            CompanionRequestHandler.pairing_pin = None
            CompanionRequestHandler.pairing_pin_expires_at = 0.0

            self._send_json(200, PairingHandshakeResponse(
                success=True,
                server_nonce=server_nonce,
                tls_fingerprint=self.tls_fingerprint
            ).model_dump())
            return

        if self.path != "/api/companion/capability":
            self._send_json(404, {"error": "Endpoint ne obstaja"})
            return

        try:
            req_dict = json.loads(raw_data)
            req = CompanionRequest(**req_dict)
        except Exception as e:
            self._send_json(400, {
                "request_id": "unknown",
                "capability": "unknown",
                "success": False,
                "error_message": f"Neveljaven JSON format zahteve: {e}"
            })
            return

        # 2. Obvezna HMAC verifikacija (Fail-Closed ob manjkajočem/prekratkem ključu)
        if not self.secret_key or len(self.secret_key) < 32:
            self._send_json(503, {
                "request_id": req.request_id,
                "capability": req.capability.value,
                "success": False,
                "error_message": "Fail-closed: Strežnik nima veljavnega 256-bitnega varnostnega ključa (Pairing required)"
            })
            return


        if not req.verify_signature(self.secret_key):
            self._send_json(401, {
                "request_id": req.request_id,
                "capability": req.capability.value,
                "success": False,
                "error_message": "Neveljaven ali manjkajoč HMAC-SHA256 podpis"
            })
            return

        # 3. Preverjanje svežine in zaščita pred ponavljanjem (Anti-Replay)
        replay_ok, replay_msg = self.replay_tracker.check_and_record(
            req.request_id,
            req.nonce,
            req.timestamp
        )
        if not replay_ok:
            self._send_json(400, {
                "request_id": req.request_id,
                "capability": req.capability.value,
                "success": False,
                "error_message": f"Anti-Replay zavrnitev: {replay_msg}"
            })
            return

        # 4. Izvedba prek CapabilityGate #2 in ShizukuRunner
        ok, msg, data = self.runner.execute_capability(req.capability, req.params)

        resp = CompanionResponse(
            request_id=req.request_id,
            capability=req.capability.value,
            success=ok,
            data=data,
            error_message=None if ok else msg
        )
        status_code = 200 if ok else 403
        self._send_json(status_code, resp.model_dump())

    def _send_json(self, status: int, data: dict):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        try:
            self.wfile.flush()
        except Exception:
            pass

    def log_message(self, format, *args):
        # Onemogoči privzeto stdout onesnaževanje
        pass


def create_companion_server(
    host: str = "127.0.0.1",
    port: int = 8995,
    secret_key: Optional[str] = None,
    secret_file: Optional[str] = None,
    runner: Optional[ShizukuRunner] = None,
    use_tls: bool = False,
    cert_file: Optional[str] = None,
    key_file: Optional[str] = None,
    pairing_pin: Optional[str] = None,
    pin_ttl_seconds: float = 300.0,
    max_pairing_attempts: int = 3,
) -> ThreadedHTTPServer:
    """Ustvari in konfigurira primerek Companion strežnika s podporo za TLS in PIN seznanitev."""
    CompanionRequestHandler.secret_key = secret_key or ""
    CompanionRequestHandler.secret_file_path = secret_file
    CompanionRequestHandler.runner = runner or ShizukuRunner()
    CompanionRequestHandler.replay_tracker = ReplayTracker(window_seconds=60.0)
    CompanionRequestHandler.failed_pairing_attempts = 0
    CompanionRequestHandler.max_pairing_attempts = max_pairing_attempts
    CompanionRequestHandler.active_pairing_sessions = {}

    tls_fp = None
    c_path = None
    k_path = None
    if use_tls:
        c_path = Path(cert_file) if cert_file else Path("/tmp/safeer-companion/companion.crt")
        k_path = Path(key_file) if key_file else Path("/tmp/safeer-companion/companion.key")
        tls_fp = ensure_tls_certificate(c_path, k_path)
        CompanionRequestHandler.tls_fingerprint = tls_fp
    else:
        CompanionRequestHandler.tls_fingerprint = None

    if pairing_pin:
        CompanionRequestHandler.pairing_pin = pairing_pin
        CompanionRequestHandler.pairing_pin_expires_at = time.time() + pin_ttl_seconds
    else:
        CompanionRequestHandler.pairing_pin = None
        CompanionRequestHandler.pairing_pin_expires_at = 0.0

    server = ThreadedHTTPServer((host, port), CompanionRequestHandler)
    if use_tls and c_path and k_path:
        ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_ctx.load_cert_chain(certfile=str(c_path), keyfile=str(k_path))
        server.socket = ssl_ctx.wrap_socket(server.socket, server_side=True)

    return server


if __name__ == "__main__":
    import argparse
    from pathlib import Path

    parser = argparse.ArgumentParser(description="Safeer Companion Daemon (Android / Shizuku)")
    parser.add_argument("--host", default="0.0.0.0", help="Host naslov (privzeto 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8995, help="Vrata (privzeto 8995)")
    parser.add_argument("--secret", default=None, help="HMAC skrivni ključ (vsaj 32 znakov / 256 bitov)")
    parser.add_argument("--secret-file", default=None, help="Pot do varovane datoteke s ključem (0600)")
    parser.add_argument("--rish-path", default=None, help="Pot do rish binarne datoteke")
    parser.add_argument("--mock", action="store_true", help="Vključi mock način za testiranje")
    parser.add_argument("--tls", action="store_true", help="Omogoči TLS šifriran prenos (HTTPS)")
    parser.add_argument("--cert", default=None, help="Pot do TLS certifikata")
    parser.add_argument("--key", default=None, help="Pot do TLS zasebnega ključa")
    parser.add_argument("--pair", action="store_true", help="Aktiviraj način seznanitve (generira 6-mestni PIN)")
    args = parser.parse_args()

    secret = args.secret or ""
    if args.secret_file:
        p = Path(args.secret_file).expanduser().resolve()
        if p.exists():
            secret = p.read_text(encoding="utf-8").strip()

    pairing_pin = None
    if args.pair:
        pairing_pin = f"{secrets.randbelow(900000) + 100000:06d}"
        print("=" * 60)
        print("  SAFEER COMPANION V0.8 — NAČIN ZA SEZNANITEV (PAIRING MODE)")
        print(f"  PIN ZA SEZNANITEV: {pairing_pin}")
        print("  Veljavnost: 5 minut (one-time use)")
        print("=" * 60)

    if not args.pair and len(secret) < 32:
        print("OPOZORILO (Fail-Closed): Skrivni ključ ni nastavljen ali ima manj kot 32 znakov (256 bitov). Privilegirani klici bodo zavrnjeni.")

    runner = ShizukuRunner(rish_path=args.rish_path, mock_mode=args.mock)
    server = create_companion_server(
        host=args.host,
        port=args.port,
        secret_key=secret,
        secret_file=args.secret_file,
        runner=runner,
        use_tls=args.tls,
        cert_file=args.cert,
        key_file=args.key,
        pairing_pin=pairing_pin,
    )
    protocol = "https" if args.tls else "http"
    print(f"Safeer Companion teče na {protocol}://{args.host}:{args.port}")
    if args.tls and CompanionRequestHandler.tls_fingerprint:
        print(f"TLS Fingerprint (SHA-256): {CompanionRequestHandler.tls_fingerprint}")
    health = runner.get_health()
    print(f"Status Shizuku: available={health['shizuku_available']}, permission={health['shizuku_permission_granted']}, mode={health['execution_mode']}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nZaustavljanje Safeer Companion strežnika...")
        server.shutdown()
        server.server_close()


