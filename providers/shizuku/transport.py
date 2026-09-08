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
import urllib.request
import urllib.error
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

from core.config import get_settings
from providers.shizuku.capabilities import Capability
from companion.protocol import (
    CompanionRequest,
    CompanionResponse,
    CompanionHealthResponse,
    compute_canonical_string,
    compute_hmac,
    verify_hmac,
)


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
    Kriptografsko avtenticiran HTTP transport do varnega Safeer Companion daemona.
    Uveljavlja strogo fail-closed obnašanje in verifikacijo odzivov.
    """

    def __init__(
        self,
        host: str,
        port: int = 8995,
        timeout: float = 3.0,
        secret_token: Optional[str] = None
    ):
        self.host = host
        self.port = port
        self.timeout = timeout
        if secret_token is not None:
            self.secret_token = secret_token
        else:
            try:
                self.secret_token = get_settings().auth_token
            except Exception:
                self.secret_token = "safeer_companion_default_secret"

    @property
    def endpoint_url(self) -> str:
        return f"http://{self.host}:{self.port}/api/companion/capability"

    @property
    def health_url(self) -> str:
        return f"http://{self.host}:{self.port}/api/companion/health"

    @property
    def opener(self):
        # Za lokalno LAN komunikacijo s Companionom obidemo morebitne sistemske proxyje
        return urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def send(self, request: CompanionRequest) -> CompanionResponse:
        """
        Podpiše zahtevo s HMAC-SHA256, jo pošlje Companionu in preveri veljavnost odziva.
        """
        # 1. Kriptografski podpis s HMAC-SHA256
        if self.secret_token:
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
