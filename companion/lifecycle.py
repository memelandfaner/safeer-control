"""
Upravitelj produkcijskega življenjskega cikla za Safeer Companion (V0.9.1).
Nadzoruje stanja delovanja, zaznavanje Shizuku povezave, nadzorovane posodobitve (OTA),
preverjanje celovitosti s SHA-256, avtentičnosti z Ed25519 ter anti-downgrade zaščito.
"""

import base64
import hashlib
import os
import re
import time
import uuid
from typing import Optional, Dict, Any, Tuple, Union

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from companion.protocol import (
    CompanionLifecycleResponse,
    CompanionUpdateRequest,
    CompanionUpdateResponse,
    compute_hmac,
)

# Uradni vgrajeni Ed25519 javni ključ za verifikacijo Safeer izdaj (trust root)
DEFAULT_RELEASE_PUBLIC_KEY_HEX = "349745e0b7668bb631601f8546dbb252d7d8fb8bdaa439bc2a99d22ad50931be"


class CompanionLifecycleManager:
    """Upravitelj življenjskega cikla, verifikacije celovitosti, Ed25519 avtentičnosti in posodobitev."""

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
    def generate_release_keypair() -> Tuple[str, str]:
        """Generira nov 256-bitni Ed25519 par ključev za izdaje (private_hex, public_hex)."""
        priv = ed25519.Ed25519PrivateKey.generate()
        pub = priv.public_key()
        priv_bytes = priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        pub_bytes = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return priv_bytes.hex(), pub_bytes.hex()

    @staticmethod
    def sign_release(
        binary_bytes: bytes,
        private_key: Union[str, bytes, ed25519.Ed25519PrivateKey]
    ) -> str:
        """
        Podpiše SHA-256 kontrolni odtis binarne datoteke z Ed25519 privatnim ključem.
        Vrne 64-bajtni (128 hex znakov) digitalni podpis.
        """
        if isinstance(private_key, str):
            priv_bytes = bytes.fromhex(private_key.strip())
            priv_obj = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
        elif isinstance(private_key, (bytes, bytearray)):
            priv_obj = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(private_key))
        elif isinstance(private_key, ed25519.Ed25519PrivateKey):
            priv_obj = private_key
        else:
            raise TypeError("Neveljaven tip Ed25519 privatnega ključa")

        digest = hashlib.sha256(binary_bytes).digest()
        sig = priv_obj.sign(digest)
        return sig.hex()

    @staticmethod
    def verify_release_signature(
        binary_bytes: bytes,
        signature_hex: str,
        public_key_hex: Optional[str] = None
    ) -> bool:
        """
        Preveri verodostojnost Ed25519 digitalnega podpisa nad SHA-256 odtisom binarne datoteke.
        Privzeto uporablja vgrajeni uradni Safeer trust root ključ.
        """
        if not signature_hex or not signature_hex.strip():
            return False

        pub_hex = (public_key_hex or DEFAULT_RELEASE_PUBLIC_KEY_HEX).strip()
        try:
            pub_bytes = bytes.fromhex(pub_hex)
            sig_bytes = bytes.fromhex(signature_hex.strip())
            pub_obj = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
            digest = hashlib.sha256(binary_bytes).digest()
            pub_obj.verify(sig_bytes, digest)
            return True
        except Exception:
            return False

    @staticmethod
    def parse_version_tuple(version_str: str) -> Tuple[int, int, int]:
        """Izlušči (major, minor, patch) celoštevilsko trojico iz poljubnega niza verzije."""
        if not version_str:
            return (0, 0, 0)
        match = re.search(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", str(version_str))
        if not match:
            return (0, 0, 0)
        return (
            int(match.group(1) or 0),
            int(match.group(2) or 0),
            int(match.group(3) or 0),
        )

    @staticmethod
    def compare_versions(v1: str, v2: str) -> int:
        """
        Primerja dve semver verziji:
        Vrne  1 če je v1 > v2 (nadgradnja),
        Vrne  0 če je v1 == v2 (ponovna namestitev),
        Vrne -1 če je v1 < v2 (downgrade / zavrnitev).
        """
        t1 = CompanionLifecycleManager.parse_version_tuple(v1)
        t2 = CompanionLifecycleManager.parse_version_tuple(v2)
        if t1 > t2:
            return 1
        if t1 < t2:
            return -1
        return 0

    @staticmethod
    def prepare_update_payload(
        binary_bytes: bytes,
        secret_key: str,
        release_signature: Optional[str] = None,
        version: Optional[str] = None,
        release_private_key: Optional[Union[str, bytes]] = None,
        restart: bool = True
    ) -> CompanionUpdateRequest:
        """
        Pripravi kriptografsko avtenticiran in z Ed25519 podpisan zahtevek za posodobitev.
        """
        sha = CompanionLifecycleManager.compute_sha256(binary_bytes)
        b64_str = base64.b64encode(binary_bytes).decode("ascii")

        sig = release_signature
        if not sig and release_private_key:
            sig = CompanionLifecycleManager.sign_release(binary_bytes, release_private_key)
        elif not sig:
            env_key = os.environ.get("SAFEER_RELEASE_PRIVATE_KEY", "").strip()
            if env_key:
                sig = CompanionLifecycleManager.sign_release(binary_bytes, env_key)

        if not sig:
            raise ValueError(
                "Fail-closed: Za nadzorovano posodobitev je obvezen veljaven Ed25519 release_signature "
                "ali release_private_key (ločen trust root od seje)!"
            )

        req = CompanionUpdateRequest(
            binary_b64=b64_str,
            sha256=sha,
            release_signature=sig,
            version=version,
            restart=restart,
            timestamp=time.time(),
            nonce=uuid.uuid4().hex[:16],
        )
        req.sign(secret_key)
        return req

