"""
Safeer Companion Daemon Strežnik (V0.6).
Lahek, samostojen HTTP strežnik za Android naprave (privzeto vrata 8995).
Izvaja strogo kriptografsko preverjanje HMAC, anti-replay sledenje in CapabilityGate #2.
"""

import json
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from typing import Optional

from companion.protocol import (
    Capability,
    CompanionRequest,
    CompanionResponse,
    CompanionHealthResponse,
    ReplayTracker,
    verify_hmac,
)
from companion.runner import ShizukuRunner


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


class CompanionRequestHandler(BaseHTTPRequestHandler):
    # Dodeljeno ob zagonu strežnika
    secret_key: str = ""
    runner: ShizukuRunner = ShizukuRunner()
    replay_tracker: ReplayTracker = ReplayTracker()

    def do_GET(self):
        if self.path == "/api/companion/health":
            health = self.runner.get_health()
            self._send_json(200, health)
        else:
            self._send_json(404, {"error": "Endpoint ne obstaja"})

    def do_POST(self):
        if self.path != "/api/companion/capability":
            self._send_json(404, {"error": "Endpoint ne obstaja"})
            return

        # 1. Branje vhodnih podatkov
        content_len = int(self.headers.get("Content-Length", 0))
        if content_len <= 0 or content_len > 65536:
            self._send_json(400, {"success": False, "error_message": "Neveljavna dolžina zahteve"})
            return

        raw_data = self.rfile.read(content_len).decode("utf-8", errors="ignore")
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

        # 2. Obvezna HMAC verifikacija
        if not self.secret_key:
            self._send_json(500, {
                "request_id": req.request_id,
                "capability": req.capability.value,
                "success": False,
                "error_message": "Strežnik nima nastavljenega varnostnega ključa"
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
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        # Onemogoči privzeto stdout onesnaževanje
        pass


def create_companion_server(
    host: str = "127.0.0.1",
    port: int = 8995,
    secret_key: str = "safeer_companion_default_secret",
    runner: Optional[ShizukuRunner] = None
) -> ThreadedHTTPServer:
    """Ustvari in konfigurira primerek Companion strežnika."""
    CompanionRequestHandler.secret_key = secret_key
    CompanionRequestHandler.runner = runner or ShizukuRunner()
    CompanionRequestHandler.replay_tracker = ReplayTracker(window_seconds=60.0)

    server = ThreadedHTTPServer((host, port), CompanionRequestHandler)
    return server
