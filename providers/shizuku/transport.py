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
from typing import Dict, Any, Optional, Tuple, Union

from core.config import get_settings
from providers.shizuku.capabilities import Capability
from companion.protocol import (
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
    derive_pairing_key,
    compute_canonical_string,
    compute_hmac,
    verify_hmac,
    compute_pairing_transcript,
    derive_pairing_auth_key,
    compute_transcript_auth,
    derive_final_shared_key,
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
        if self.pinned_fingerprint:
            return "https"
        return "https" if self.use_tls else "http"

    @property
    def endpoint_url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}/api/companion/capability"

    @property
    def health_url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}/api/companion/health"

    @property
    def lifecycle_url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}/api/companion/lifecycle"

    @property
    def update_url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}/api/companion/update"

    @property
    def pairing_init_url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}/api/companion/pair/init"

    @property
    def pairing_confirm_url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}/api/companion/pair/confirm"

    @property
    def pairing_url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}/api/companion/pair/handshake"

    @property
    def opener(self):
        handlers = [urllib.request.ProxyHandler({})]
        if self.use_tls or self.pinned_fingerprint:
            handlers.append(FingerprintHTTPSHandler(pinned_fingerprint=self.pinned_fingerprint))
        return urllib.request.build_opener(*handlers)

    def handshake_pairing(self, pin: str, timeout: float = 5.0) -> Tuple[str, str]:
        """
        Izvede V0.8.1 PIN bootstrap seznanitev preko TLS povezave z mutual transcript potrditvijo
        in channel bindingom TLS certifikata.
        Vrne tuple (derived_secret_key, tls_fingerprint).
        """
        clean_pin = pin.strip()
        if not clean_pin or len(clean_pin) < 4:
            raise ValueError("PIN mora vsebovati vsaj 4 znake (priporočeno 6 števk).")

        client_nonce = secrets.token_hex(16)
        init_req = PairingInitRequest(client_nonce=client_nonce)
        payload_init = init_req.model_dump_json().encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "SafeerControl-Transport/0.8.1",
        }

        # TLS bootstrap seznanitev vedno teče prek HTTPS
        url_init = f"https://{self.host}:{self.port}/api/companion/pair/init"
        url_confirm = f"https://{self.host}:{self.port}/api/companion/pair/confirm"

        handler = FingerprintHTTPSHandler(pinned_fingerprint=self.pinned_fingerprint)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), handler)

        # 1. Korak: POST /api/companion/pair/init (izmenjava nonces in pridobitev certifikata)
        http_req_init = urllib.request.Request(
            url=url_init,
            data=payload_init,
            headers=headers,
            method="POST"
        )

        try:
            with opener.open(http_req_init, timeout=timeout) as resp:
                raw_body = resp.read().decode("utf-8", errors="ignore")
                data = json.loads(raw_body)
                init_resp = PairingInitResponse(**data)

                if not init_resp.success or not init_resp.server_nonce:
                    err = init_resp.error_message or "Seznanitev zavrnjena na koraku init"
                    raise ValueError(f"Handshake init failed: {err}")

                server_nonce = init_resp.server_nonce
                server_reported_fp = init_resp.tls_fingerprint

                conn_fp = None
                if handler.last_connection and handler.last_connection.peer_fingerprint:
                    conn_fp = handler.last_connection.peer_fingerprint

                if not conn_fp and not server_reported_fp:
                    raise ssl.SSLCertVerificationError("Fail-closed: TLS certifikata ni bilo mogoče pridobiti.")

                peer_fp = (conn_fp or server_reported_fp).lower()

                if server_reported_fp and conn_fp and server_reported_fp.lower() != conn_fp.lower():
                    raise ssl.SSLCertVerificationError(
                        f"Fail-closed: TLS fingerprint neskladje med TLS povezavo ({conn_fp}) in vsebino odziva ({server_reported_fp})"
                    )

                # 2. Korak: Vezava transkripta (Channel Binding) in izpeljava avtentikacije
                transcript = compute_pairing_transcript(client_nonce, server_nonce, peer_fp)
                auth_key = derive_pairing_auth_key(clean_pin, client_nonce, server_nonce)
                client_auth = compute_transcript_auth(auth_key, transcript, role="client")

                confirm_req = PairingConfirmRequest(
                    client_nonce=client_nonce,
                    client_auth=client_auth
                )
                confirm_payload = confirm_req.model_dump_json().encode("utf-8")

                http_req_confirm = urllib.request.Request(
                    url=url_confirm,
                    data=confirm_payload,
                    headers=headers,
                    method="POST"
                )

                with opener.open(http_req_confirm, timeout=timeout) as resp_confirm:
                    conf_raw = resp_confirm.read().decode("utf-8", errors="ignore")
                    conf_data = json.loads(conf_raw)
                    conf_resp = PairingConfirmResponse(**conf_data)

                    if not conf_resp.success or not conf_resp.server_auth:
                        err = conf_resp.error_message or "Potrditev transkripta seznanitve ni uspela"
                        raise ValueError(f"Handshake confirm failed: {err}")

                    expected_server_auth = compute_transcript_auth(auth_key, transcript, role="server")
                    if not secrets.compare_digest(conf_resp.server_auth.lower(), expected_server_auth.lower()):
                        raise ssl.SSLCertVerificationError(
                            "Fail-closed: Strežnik ni poslal veljavne avtentikacije transkripta (možen MITM napad!)"
                        )

                    final_key = derive_final_shared_key(auth_key, transcript)

                    self.secret_token = final_key
                    self.pinned_fingerprint = peer_fp
                    self.use_tls = True

                    return final_key, peer_fp

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
            req = urllib.request.Request(self.health_url, headers={"User-Agent": "SafeerControl-Transport/0.9"})
            with self.opener.open(req, timeout=1.5) as resp:
                if resp.status != 200:
                    return False
                raw_body = resp.read().decode("utf-8", errors="ignore")
                data = json.loads(raw_body)
                health = CompanionHealthResponse(**data)
                return bool(health.companion_running and health.shizuku_available and health.shizuku_permission_granted)
        except Exception:
            return False

    def get_lifecycle(self) -> Optional[CompanionLifecycleResponse]:
        """Pridobi strukturirano poročilo o življenjskem ciklu Companion daemona."""
        try:
            req = urllib.request.Request(self.lifecycle_url, headers={"User-Agent": "SafeerControl-Transport/0.9"})
            with self.opener.open(req, timeout=self.timeout) as resp:
                if resp.status != 200:
                    return None
                raw_body = resp.read().decode("utf-8", errors="ignore")
                data = json.loads(raw_body)
                return CompanionLifecycleResponse(**data)
        except Exception:
            return None

    def update_companion(
        self,
        binary_bytes: bytes,
        release_signature: Optional[str] = None,
        version: Optional[str] = None,
        release_private_key: Optional[Union[str, bytes]] = None,
        restart: bool = True
    ) -> CompanionUpdateResponse:
        """Izvede nadzorovano posodobitev (OTA) Companion binarnega programa z Ed25519 avtentikacijo."""
        if not self.secret_token or len(self.secret_token) < 32:
            return CompanionUpdateResponse(
                success=False,
                error_message="Fail-closed: Skrivni ključ za posodobitev ni na voljo (Pairing required)."
            )

        from companion.lifecycle import CompanionLifecycleManager
        try:
            payload_obj = CompanionLifecycleManager.prepare_update_payload(
                binary_bytes=binary_bytes,
                secret_key=self.secret_token,
                release_signature=release_signature,
                version=version,
                release_private_key=release_private_key,
                restart=restart
            )
        except Exception as e:
            return CompanionUpdateResponse(
                success=False,
                error_message=f"Priprava posodobitve zavrnjena (Fail-Closed): {e}"
            )
        payload_bytes = payload_obj.model_dump_json().encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "SafeerControl-Transport/0.9.1",
        }

        http_req = urllib.request.Request(
            url=self.update_url,
            data=payload_bytes,
            headers=headers,
            method="POST"
        )

        try:
            with self.opener.open(http_req, timeout=10.0) as resp:
                raw_body = resp.read().decode("utf-8", errors="ignore")
                data = json.loads(raw_body)
                return CompanionUpdateResponse(**data)
        except urllib.error.HTTPError as e:
            err_msg = ""
            try:
                err_body = e.read().decode("utf-8", errors="ignore")
                err_json = json.loads(err_body)
                err_msg = err_json.get("error_message", str(e))
            except Exception:
                err_msg = str(e)
            return CompanionUpdateResponse(
                success=False,
                error_message=f"Posodobitev zavrnjena (HTTP {e.code}): {err_msg}"
            )
        except Exception as e:
            return CompanionUpdateResponse(
                success=False,
                error_message=f"Napaka pri posodobitvi: {e}"
            )
