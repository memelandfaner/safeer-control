"""
Strukturiran transportni protokol med Safeer Control in Safeer Companion (V0.5.1).
Uveljavlja fail-closed obnašanje brez kakršnegakoli zanašanja na ADB ali subprocess.
"""

import json
import time
import uuid
import urllib.request
import urllib.error
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field

from providers.shizuku.capabilities import Capability


class CompanionRequest(BaseModel):
    """Tipizirana zahteva za Safeer Companion na Android napravi."""
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    capability: Capability
    params: Dict[str, Any] = Field(default_factory=dict)
    timestamp: float = Field(default_factory=time.time)
    token_hash: Optional[str] = None


class CompanionResponse(BaseModel):
    """Tipiziran odgovor Safeer Companion-a."""
    request_id: str
    capability: str
    success: bool
    data: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None


class BaseCompanionTransport(ABC):
    """Abstraktni vmesnik za varno posredovanje tipiziranih zmožnosti Companionu."""

    @abstractmethod
    def send(self, request: CompanionRequest) -> CompanionResponse:
        """Pošlje tipizirano zahtevo Companionu in vrne tipiziran odgovor."""
        pass

    @abstractmethod
    def check_health(self) -> bool:
        """Preveri razpoložljivost Companion storitve."""
        pass


class HttpCompanionTransport(BaseCompanionTransport):
    """
    HTTP REST / JSON transport do varnega Safeer Companion daemona na napravi.
    Uveljavlja strogo fail-closed obnašanje.
    """

    def __init__(self, host: str, port: int = 8995, timeout: float = 3.0, secret_token: Optional[str] = None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.secret_token = secret_token

    @property
    def endpoint_url(self) -> str:
        return f"http://{self.host}:{self.port}/api/companion/capability"

    @property
    def health_url(self) -> str:
        return f"http://{self.host}:{self.port}/api/companion/health"

    def send(self, request: CompanionRequest) -> CompanionResponse:
        """
        Pošlje zahtevo Companionu. Ob vsaki omrežni ali protokoli napaki vrne fail-closed odgovor!
        """
        payload_bytes = request.model_dump_json().encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "SafeerControl-Transport/0.5.1",
            "X-Safeer-Request-Id": request.request_id,
        }
        if self.secret_token:
            headers["X-Safeer-Companion-Token"] = self.secret_token

        http_req = urllib.request.Request(
            url=self.endpoint_url,
            data=payload_bytes,
            headers=headers,
            method="POST"
        )

        try:
            with urllib.request.urlopen(http_req, timeout=self.timeout) as resp:
                if resp.status != 200:
                    return CompanionResponse(
                        request_id=request.request_id,
                        capability=request.capability.value,
                        success=False,
                        error_message=f"Fail-closed: Companion vrnil neveljaven status {resp.status}."
                    )
                raw_body = resp.read().decode("utf-8", errors="ignore")
                data = json.loads(raw_body)
                return CompanionResponse(
                    request_id=data.get("request_id", request.request_id),
                    capability=data.get("capability", request.capability.value),
                    success=bool(data.get("success", False)),
                    data=data.get("data"),
                    error_message=data.get("error_message")
                )
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
        try:
            req = urllib.request.Request(self.health_url, headers={"User-Agent": "SafeerControl-Transport/0.5.1"})
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                return resp.status == 200
        except Exception:
            return False
