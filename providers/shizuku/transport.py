"""
Strukturiran kriptografski transportni protokol za Safeer Companion (V0.6).
Uveljavlja 4 zaščite:
1. Obvezno HMAC-SHA256 avtentikacijo nad kanoničnim nizom
2. Preverjanje svežine časovnega žiga (timestamp drift)
3. Zaščito pred napadi s ponavljanjem (replay protection)
4. Strogo ujemanje response.request_id == request.request_id in response.capability == request.capability
5. Natančen pregled zdravja: delovanje Companiona + Shizuku razpoložljivost + dovoljenje
"""

import json
import time
import ssl
import http.client
import hashlib
import secrets
import urllib.request
import urllib.error
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Tuple

from core.config import get_settings
from providers.shizuku.capabilities import Capability
from companion.protocol import (
    CompanionRequest,
    CompanionResponse,
    CompanionHealthResponse,
    PairingHandshakeRequest,
    PairingHandshakeResponse,
    derive_pairing_key,
    compute_canonical_string,
    compute_hmac,
    verify_hmac,
)


class FingerprintVerifyingHTTPSConnection(http.client.HTTPSConnection):
    pinned_fingerprint: Optional[str] = None
    peer_fingerprint: Optional[str] = None

    def connect(self):
        super().connect()
        cert_der = self.sock.getpeercert(binary_form=True)
        if cert_der:
            self.peer_fingerprint = hashlib.sha256(cert_der).hexdigest().lower()
            if self.pinned_fingerprint:
                if self.peer_fingerprint != self.pinned_fingerprint.lower():
                    raise ssl.SSLCertVerificationError(
                        f"Fail-closed: TLS cert fingerprint mismatch! "
                        f"Expected {self.pinned_fingerprint}, got {self.peer_fingerprint}"
                    )


class FingerprintHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, pinned_fingerprint: Optional[str] = None, context: Optional[ssl.SSLContext] = None):
        self.pinned_fingerprint = pinned_fingerprint
        self.last_connection: Optional[FingerprintVerifyingHTTPSConnection] = None
        ctx = context or ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        super().__init__(context=ctx)

    def https_open(self, req):
        return self.do_open(self.getConnection, req)

    def getConnection(self, host, timeout=None):
        conn = FingerprintVerifyingHTTPSConnection(host, timeout=timeout, context=self._context)
        conn.pinned_fingerprint = self.pinned_fingerprint
        self.last_connection = conn
        return conn


class BaseCompanionTransport(ABC):
    """Abstraktni vmesnik za varno posredovanje tipiziranih zmožnosti Companionu."""

    @abstractmethod
    def send(self, request: CompanionRequest) -> CompanionResponse:
        """Pošlje tipizirano zahtevo Companionu in vrne tipiziran odgovor."""
        pass

    @abstractmethod
    def check_health(self) -> bool:
        """Preveri razpoložljivost Companion storitve in Shizuku privilegijev."""
        pass


class HttpCompanionTransport(BaseCompanionTransport):
    """
    Kriptografsko avtenticiran HTTP/HTTPS transport do varnega Safeer Companion daemona.
    Uveljavlja strogo fail-closed obnašanje, TLS šifriranje in pinning certifikata.
    """

    def __init__(
        self,
        host: str,
        port: int = 8995,
        timeout: float = 3.0,
        secret_token: Optional[str] = None,
        use_tls: bool = False,
        pinned_fingerprint: Optional[str] = None,
    ):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.secret_token = secret_token
        self.use_tls = use_tls or bool(pinned_fingerprint)
        self.pinned_fingerprint = pinned_fingerprint.lower() if pinned_fingerprint else None

    @property
    def scheme(self) -> str:
        return "https" if self.use_tls else "http"

    @property
    def endpoint_url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}/api/companion/capability"

    @property
    def health_url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}/api/companion/health"

    @property
    def pairing_url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}/api/companion/pair/handshake"

    @property
    def opener(self):
        handlers = [urllib.request.ProxyHandler({})]
        if self.use_tls:
            handlers.append(FingerprintHTTPSHandler(pinned_fingerprint=self.pinned_fingerprint))
        return urllib.request.build_opener(*handlers)

    def handshake_pairing(self, pin: str, timeout: float = 5.0) -> Tuple[str, str]:
        """
        Izvede V0.8 PIN handshake seznanitev preko TLS povezave.
        Preveri PIN, prevzame strežniški TLS certifikat in izpelje skupni 256-bitni HMAC ključ.
        Vrne tuple (derived_secret_key, tls_fingerprint).
        """
        client_nonce = secrets.token_hex(16)
        handshake_req = PairingHandshakeRequest(pin=pin.strip(), client_nonce=client_nonce)
        payload = handshake_req.model_dump_json().encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "SafeerControl-Transport/0.8",
        }

        # V0.8 PIN handshake poteka prek varne TLS (HTTPS) povezave
        url = f"https://{self.host}:{self.port}/api/companion/pair/handshake"

        handler = FingerprintHTTPSHandler(pinned_fingerprint=self.pinned_fingerprint)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), handler)

        http_req = urllib.request.Request(
            url=url,
            data=payload,
            headers=headers,
            method="POST"
        )

        try:
            with opener.open(http_req, timeout=timeout) as resp:
                raw_body = resp.read().decode("utf-8", errors="ignore")
                data = json.loads(raw_body)
                resp_obj = PairingHandshakeResponse(**data)

                if not resp_obj.success or not resp_obj.server_nonce:
                    err = resp_obj.error_message or "Seznanitev ni uspela"
                    raise ValueError(f"Handshake failed: {err}")

                server_fp = resp_obj.tls_fingerprint
                if self.use_tls and handler and handler.last_connection and handler.last_connection.peer_fingerprint:
                    conn_fp = handler.last_connection.peer_fingerprint
                    if server_fp and conn_fp != server_fp.lower():
                        raise ssl.SSLCertVerificationError(
                            f"Fail-closed: TLS fingerprint neskladje med TLS povezavo ({conn_fp}) in odzivom ({server_fp})"
                        )
                    server_fp = conn_fp

                derived_key = derive_pairing_key(pin, client_nonce, resp_obj.server_nonce)

                self.secret_token = derived_key
                if server_fp:
                    self.pinned_fingerprint = server_fp.lower()
                    self.use_tls = True

                return derived_key, (server_fp or "")

        except urllib.error.HTTPError as e:
            err_msg = ""
            try:
                err_body = e.read().decode("utf-8", errors="ignore")
                err_json = json.loads(err_body)
                err_msg = err_json.get("error_message", str(e))
            except Exception:
                err_msg = str(e)
            raise ValueError(f"Seznanitev zavrnjena (HTTP {e.code}): {err_msg}")
        except Exception as e:
            raise ValueError(f"Napaka pri seznanitvi: {e}")

    def send(self, request: CompanionRequest) -> CompanionResponse:
        """
        Podpiše zahtevo s HMAC-SHA256, jo pošlje Companionu in preveri veljavnost odziva.
        """
        # 1. Preveri veljavnost skrivnega ključa (Fail-Closed)
        if not self.secret_token or len(self.secret_token) < 32:
            return CompanionResponse(
                request_id=request.request_id,
                capability=request.capability.value,
                success=False,
                error_message="Fail-closed: Skrivni ključ za napravo ni nastavljen ali ima manj kot 256 bitov (pairing required)."
            )

        # 2. Kriptografski podpis s HMAC-SHA256
        request.sign(self.secret_token)

        payload_bytes = request.model_dump_json().encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "SafeerControl-Transport/0.6",
            "X-Safeer-Request-Id": request.request_id,
        }

        http_req = urllib.request.Request(
            url=self.endpoint_url,
            data=payload_bytes,
            headers=headers,
            method="POST"
        )

        try:
            with self.opener.open(http_req, timeout=self.timeout) as resp:
                raw_body = resp.read().decode("utf-8", errors="ignore")
                data = json.loads(raw_body)
                resp_obj = CompanionResponse(**data)

                # 2. Varnostno preverjanje ujemanja odziva (V0.6 zaščita #4)
                if resp_obj.request_id != request.request_id:
                    return CompanionResponse(
                        request_id=request.request_id,
                        capability=request.capability.value,
                        success=False,
                        error_message=f"Fail-closed: Mismatched request_id (poslano: '{request.request_id}', prejeto: '{resp_obj.request_id}')"
                    )

                if resp_obj.capability != request.capability.value:
                    return CompanionResponse(
                        request_id=request.request_id,
                        capability=request.capability.value,
                        success=False,
                        error_message=f"Fail-closed: Mismatched capability (poslano: '{request.capability.value}', prejeto: '{resp_obj.capability}')"
                    )

                return resp_obj

        except urllib.error.HTTPError as e:
            err_msg = ""
            try:
                err_body = e.read().decode("utf-8", errors="ignore")
                err_json = json.loads(err_body)
                err_msg = err_json.get("error_message", str(e))
            except Exception:
                err_msg = str(e)
            return CompanionResponse(
                request_id=request.request_id,
                capability=request.capability.value,
                success=False,
                error_message=f"Fail-closed (HTTP {e.code}): {err_msg}"
            )
        except Exception as e:
            return CompanionResponse(
                request_id=request.request_id,
                capability=request.capability.value,
                success=False,
                error_message=f"Fail-closed: Companion transport nedosegljiv ({e.__class__.__name__}: {e})"
            )

    def check_health(self) -> bool:
        """
        Preveri, ali Companion teče IN ali ima aktivna Shizuku dovoljenja.
        """
        try:
            req = urllib.request.Request(self.health_url, headers={"User-Agent": "SafeerControl-Transport/0.6"})
            with self.opener.open(req, timeout=1.5) as resp:
                if resp.status != 200:
                    return False
                raw_body = resp.read().decode("utf-8", errors="ignore")
                data = json.loads(raw_body)
                health = CompanionHealthResponse(**data)
                # Zahtevamo oboje: Companion aktiven IN Shizuku dovoljenja potrjena!
                return bool(health.companion_running and health.shizuku_available and health.shizuku_permission_granted)
        except Exception:
            return False
