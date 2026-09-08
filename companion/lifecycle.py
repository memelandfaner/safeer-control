"""
Upravitelj produkcijskega življenjskega cikla za Safeer Companion (V0.9).
Nadzoruje stanja delovanja, zaznavanje Shizuku povezave, nadzorovane posodobitve (OTA)
ter preverjanje celovitosti binarnega programa s SHA-256.
"""

import base64
import hashlib
import time
import uuid
from typing import Optional, Dict, Any

from companion.protocol import (
    CompanionLifecycleResponse,
    CompanionUpdateRequest,
    CompanionUpdateResponse,
    compute_hmac,
)


class CompanionLifecycleManager:
    """Upravitelj življenjskega cikla, verifikacije celovitosti in nadzorovanih posodobitev."""

    @staticmethod
    def compute_sha256(binary_bytes: bytes) -> str:
        """Izračuna heksadecimalni SHA-256 prstni odtis binarne datoteke."""
        return hashlib.sha256(binary_bytes).hexdigest().lower()

    @staticmethod
    def verify_integrity(binary_bytes: bytes, expected_sha256: str) -> bool:
        """Kriptografsko preveri ujemanje SHA-256 kontrolnega odtisa."""
        actual = CompanionLifecycleManager.compute_sha256(binary_bytes)
        return actual == expected_sha256.strip().lower()

    @staticmethod
    def prepare_update_payload(
        binary_bytes: bytes,
        secret_key: str,
        restart: bool = True
    ) -> CompanionUpdateRequest:
        """
        Pripravi kriptografsko podpisan zahtevek za posodobitev s SHA-256 kontrolno vsoto.
        """
        sha = CompanionLifecycleManager.compute_sha256(binary_bytes)
        b64_str = base64.b64encode(binary_bytes).decode("ascii")
        req = CompanionUpdateRequest(
            binary_b64=b64_str,
            sha256=sha,
            restart=restart,
            timestamp=time.time(),
            nonce=uuid.uuid4().hex[:16],
        )
        req.sign(secret_key)
        return req
