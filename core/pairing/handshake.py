"""
Pairing Handshake modul za varno povezovanje naprav in preverjanje pristnosti (tokens / pin).
"""

import hmac
import hashlib
import secrets
from typing import Optional, Dict
from core.config import get_settings


class DevicePairing:
    """
    Upravljanje seznanjanja naprav s kriptografskim žetonom ali PIN-om.
    """

    def __init__(self):
        self._paired_tokens: Dict[str, str] = {}

    def generate_pairing_pin(self, device_id: str) -> str:
        """Ustvari 6-mestni PIN za seznanjanje nove naprave."""
        pin = f"{secrets.randbelow(900000) + 100000}"
        self._paired_tokens[device_id] = pin
        return pin

    def verify_pin(self, device_id: str, pin: str) -> bool:
        """Preveri veljavnost PIN kode."""
        expected = self._paired_tokens.get(device_id)
        if expected and hmac.compare_digest(expected, pin):
            del self._paired_tokens[device_id]
            return True
        return False

    def verify_auth_token(self, provided_token: Optional[str]) -> bool:
        """Preveri globalni avtentikacijski žeton, če je nastavljen."""
        settings = get_settings()
        if not settings.auth_token:
            return True  # Če žeton ni nastavljen, je lokalno omrežje zaupanja vredno
        if not provided_token:
            return False
        return hmac.compare_digest(settings.auth_token, provided_token)
