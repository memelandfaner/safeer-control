"""
Pairing Handshake modul za varno povezovanje naprav in preverjanje pristnosti (tokens / pin / kriptografska identiteta).
Uveljavlja Safeer Trust Model:
- Omrežni lokator (IP/MAC/mDNS): Kje je naprava?
- Safeer Device Key / Identity: Ali je to res moja naprava?
"""

import hmac
import hashlib
import secrets
import uuid
from typing import Optional, Dict, Tuple
from core.config import get_settings
from core.devices.models import DeviceIdentity


class DevicePairing:
    """
    Upravljanje seznanjanja naprav s kriptografskim žetonom ali PIN-om.
    """

    def __init__(self):
        self._pending_pins: Dict[str, str] = {}
        self._paired_identities: Dict[str, DeviceIdentity] = {}

    def generate_pairing_pin(self, device_id: str) -> str:
        """Ustvari 6-mestni PIN za seznanjanje nove naprave."""
        pin = f"{secrets.randbelow(900000) + 100000}"
        self._pending_pins[device_id] = pin
        return pin

    def verify_pin(self, device_id: str, pin: str) -> bool:
        """Preveri veljavnost PIN kode."""
        expected = self._pending_pins.get(device_id)
        if expected and hmac.compare_digest(expected, pin):
            del self._pending_pins[device_id]
            return True
        return False

    def create_paired_identity(self, device_id: str) -> Tuple[DeviceIdentity, str]:
        """
        Ustvari novo kriptografsko identiteto naprave in pripadajoči tajni žeton (Shared Secret).
        Vrne (DeviceIdentity z izračunanim HMAC zgoščkom, surovi tajni žeton).
        """
        raw_secret = secrets.token_hex(32)
        dev_uuid = str(uuid.uuid4())
        salt = get_settings().auth_token.encode("utf-8")
        token_hash = hmac.new(salt, raw_secret.encode("utf-8"), hashlib.sha256).hexdigest()

        identity = DeviceIdentity(
            device_uuid=dev_uuid,
            trusted=True,
            fingerprint=f"safeer-dev-{dev_uuid[:8]}",
            auth_token_hash=token_hash
        )
        self._paired_identities[device_id] = identity
        return identity, raw_secret

    def verify_device_token(self, identity: DeviceIdentity, provided_secret: str) -> bool:
        """
        Preveri, ali predloženi tajni žeton ustreza kriptografski identiteti naprave.
        """
        if not identity.auth_token_hash or not provided_secret:
            return False
        salt = get_settings().auth_token.encode("utf-8")
        computed_hash = hmac.new(salt, provided_secret.encode("utf-8"), hashlib.sha256).hexdigest()
        return hmac.compare_digest(identity.auth_token_hash, computed_hash)

    def verify_auth_token(self, provided_token: Optional[str]) -> bool:
        """Preveri globalni Safeer avtentikacijski žeton."""
        settings = get_settings()
        if not provided_token:
            return False
        return hmac.compare_digest(settings.auth_token, provided_token)


_pairing_instance: Optional[DevicePairing] = None


def get_device_pairing() -> DevicePairing:
    global _pairing_instance
    if _pairing_instance is None:
        _pairing_instance = DevicePairing()
    return _pairing_instance
