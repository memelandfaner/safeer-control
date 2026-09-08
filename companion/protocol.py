"""
Kriptografski protokol za Safeer Companion (V0.6).
Vključuje:
1. Kanonično serializacijo zahtev
2. HMAC-SHA256 podpisovanje in verifikacijo
3. Preverjanje svežine časovnega žiga (Timestamp drift)
4. Zaščito pred napadi s ponavljanjem (Anti-Replay Tracker)
5. Tipizirana modela zahteve in odgovora
"""

import hmac
import hashlib
import json
import time
import uuid
from enum import Enum
from typing import Dict, Any, Optional, Tuple
from pydantic import BaseModel, Field


class Capability(str, Enum):
    APP_FORCE_STOP = "app.force_stop"
    SETTINGS_READ = "settings.read"
    APP_CACHE_MAINTENANCE = "app.cache_maintenance"


def compute_canonical_string(
    request_id: str,
    timestamp: float,
    nonce: str,
    capability: str,
    params: Dict[str, Any]
) -> str:
    """
    Sestavi determinističen kanonični niz za podpisovanje.
    Format: request_id:timestamp:nonce:capability:canonical_json(params)
    """
    canonical_params = json.dumps(params, sort_keys=True, separators=(",", ":"))
    ts_int = int(timestamp)
    return f"{request_id}:{ts_int}:{nonce}:{capability}:{canonical_params}"


MIN_SECRET_LENGTH = 32  # Minimalno 256 bitov


def compute_hmac(secret_key: str, canonical_string: str) -> str:
    """Izračuna varen HMAC-SHA256 podpis."""
    if not secret_key or len(secret_key) < MIN_SECRET_LENGTH:
        raise ValueError(
            f"Skrivni ključ (secret_key) mora imeti vsaj {MIN_SECRET_LENGTH} znakov (256 bitov) za varno avtentikacijo."
        )
    return hmac.new(
        secret_key.encode("utf-8"),
        canonical_string.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


def verify_hmac(secret_key: str, canonical_string: str, expected_signature: str) -> bool:
    """Varno preveri ujemanje HMAC podpisa (konstantni čas preverjanja proti timing napadom)."""
    if not secret_key or len(secret_key) < MIN_SECRET_LENGTH or not expected_signature:
        return False
    try:
        actual = compute_hmac(secret_key, canonical_string)
        return hmac.compare_digest(actual, expected_signature)
    except Exception:
        return False



class ReplayTracker:
    """
    Sledi uporabljenim request_id in nonce z drsečim časovnim oknom (privzeto 60s).
    Preprečuje napade s ponavljanjem (replay attacks).
    """

    def __init__(self, window_seconds: float = 60.0):
        self.window_seconds = window_seconds
        self._seen: Dict[str, float] = {}

    def check_and_record(self, request_id: str, nonce: str, timestamp: float) -> Tuple[bool, str]:
        now = time.time()
        # 1. Preveri svežino časovnega žiga (drift)
        drift = abs(now - timestamp)
        if drift > self.window_seconds:
            return False, f"Zahteva je potekla ali uro zamuja (drift: {drift:.1f}s > {self.window_seconds}s)"

        # 2. Čiščenje starih zapisov
        cutoff = now - self.window_seconds
        self._seen = {k: ts for k, ts in self._seen.items() if ts > cutoff}

        # 3. Preveri replay
        composite_key = f"{request_id}:{nonce}"
        if composite_key in self._seen:
            return False, f"Zaznan napad s ponavljanjem (Replay attack): request_id '{request_id}' je že bil uporabljen."

        self._seen[composite_key] = now
        return True, "OK"


class CompanionRequest(BaseModel):
    """Tipizirana zahteva za Safeer Companion z obveznimi varnostnimi polji."""
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = Field(default_factory=time.time)
    nonce: str = Field(default_factory=lambda: uuid.uuid4().hex[:16])
    capability: Capability
    params: Dict[str, Any] = Field(default_factory=dict)
    signature: Optional[str] = None

    def sign(self, secret_key: str) -> None:
        """Podpiše zahtevo s HMAC-SHA256 nad kanoničnim nizom."""
        canon = compute_canonical_string(
            self.request_id,
            self.timestamp,
            self.nonce,
            self.capability.value,
            self.params
        )
        self.signature = compute_hmac(secret_key, canon)

    def verify_signature(self, secret_key: str) -> bool:
        """Preveri HMAC podpis zahteve."""
        if not self.signature:
            return False
        canon = compute_canonical_string(
            self.request_id,
            self.timestamp,
            self.nonce,
            self.capability.value,
            self.params
        )
        return verify_hmac(secret_key, canon, self.signature)


class CompanionResponse(BaseModel):
    """Tipiziran odgovor Safeer Companion-a."""
    request_id: str
    capability: str
    success: bool
    data: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None


class CompanionHealthResponse(BaseModel):
    """Strukturirano poročilo o zdravju Companion storitve in Shizuku privilegijih."""
    status: str = "ok"
    version: Optional[str] = "0.9.0"
    protocol_version: str = "1.0"
    companion_running: bool = True
    shizuku_available: bool = True
    shizuku_permission_granted: bool = True
    shizuku_state: Optional[str] = "ready"
    uptime_seconds: Optional[float] = None
    pid: Optional[int] = None
    details: Optional[Any] = None


class CompanionLifecycleResponse(BaseModel):
    """Podrobno poročilo o življenjskem ciklu Companion daemona."""
    status: str = "ok"
    version: str = "0.9.0"
    protocol_version: str = "1.1"
    companion_running: bool = True
    uptime_seconds: float = 0.0
    pid: Optional[int] = None
    shizuku_available: bool = True
    shizuku_permission_granted: bool = True
    shizuku_state: str = "ready"  # "ready" | "waiting_for_shizuku" | "permission_denied"
    details: Optional[Any] = None
    execution_mode: str = "rish"
    tls_enabled: bool = False
    tls_fingerprint: Optional[str] = None
    pairing_active: bool = False
    memory_alloc_kb: Optional[int] = None
    supported_capabilities: list[str] = Field(default_factory=list)


class CompanionUpdateRequest(BaseModel):
    """Zahteva za nadzorovano posodobitev (OTA) Companion binarne datoteke z Ed25519 preverjanjem."""
    binary_b64: str
    sha256: str
    release_signature: str
    version: Optional[str] = None
    restart: bool = True
    timestamp: float = Field(default_factory=time.time)
    nonce: str = Field(default_factory=lambda: uuid.uuid4().hex[:16])
    signature: Optional[str] = None

    def compute_canon(self) -> str:
        sig_norm = self.release_signature.strip().lower() if self.release_signature else ""
        return f"update:{int(self.timestamp)}:{self.nonce}:{self.sha256.lower()}:{sig_norm}"

    def sign(self, secret_key: str) -> None:
        canon = self.compute_canon()
        self.signature = compute_hmac(secret_key, canon)

    def verify_signature(self, secret_key: str) -> bool:
        if not self.signature:
            return False
        canon = self.compute_canon()
        return verify_hmac(secret_key, canon, self.signature)



class CompanionUpdateResponse(BaseModel):
    """Odgovor na zahtevo za nadzorovano posodobitev."""
    success: bool
    old_version: Optional[str] = None
    new_version: Optional[str] = None
    message: str = ""
    error_message: Optional[str] = None


class PairingHandshakeRequest(BaseModel):
    """Zahteva za varno seznanitev (V0.8 PIN handshake)."""
    pin: str
    client_nonce: str


class PairingHandshakeResponse(BaseModel):
    """Odgovor na seznanitev z izmenjanim strežniškim noncom in TLS certifikatom."""
    success: bool
    server_nonce: Optional[str] = None
    tls_fingerprint: Optional[str] = None
    error_message: Optional[str] = None


class PairingInitRequest(BaseModel):
    """V0.8.1 Korak 1: Zahteva za inicializacijo seznanitve s strani odjemalca."""
    client_nonce: str


class PairingInitResponse(BaseModel):
    """V0.8.1 Korak 1: Odgovor strežnika z noncom in TLS prstnim odtisom."""
    success: bool
    server_nonce: Optional[str] = None
    tls_fingerprint: Optional[str] = None
    error_message: Optional[str] = None


class PairingConfirmRequest(BaseModel):
    """V0.8.1 Korak 2: Zahteva za potrditev z overitvijo kanoničnega transkripta."""
    client_nonce: str
    client_auth: str


class PairingConfirmResponse(BaseModel):
    """V0.8.1 Korak 2: Odgovor strežnika z overitvijo strežniškega transkripta."""
    success: bool
    server_auth: Optional[str] = None
    error_message: Optional[str] = None


def compute_pairing_transcript(
    client_nonce: str,
    server_nonce: str,
    cert_fingerprint: str
) -> str:
    """
    Sestavi determinističen kanonični transkript, ki kriptografsko veže
    oba naključna nonca in SHA-256 prstni odtis TLS certifikata seje.
    Format: safeer-bootstrap-v0.8.1:<client_nonce>:<server_nonce>:<cert_fingerprint_lower>
    """
    fp_clean = cert_fingerprint.strip().lower()
    return f"safeer-bootstrap-v0.8.1:{client_nonce}:{server_nonce}:{fp_clean}"


def derive_pairing_auth_key(
    pin: str,
    client_nonce: str,
    server_nonce: str
) -> bytes:
    """
    Izpelje 32-bajtni začasni avtentikacijski ključ iz nizkoentropijskega PIN-a
    in obeh noncov z uporabo standardnega RFC 5869 HKDF-SHA256.
    """
    ikm = pin.strip().encode("utf-8")
    salt = f"{client_nonce}:{server_nonce}".encode("utf-8")
    info = b"safeer-pake-auth-v0.8.1"

    # HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()

    # HKDF-Expand: T(1) = HMAC-SHA256(PRK, info || 0x01)
    t1 = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
    return t1[:32]


def compute_transcript_auth(
    auth_key: bytes,
    transcript: str,
    role: str = "client"
) -> str:
    """
    Izračuna HMAC-SHA256 potrditveni žeton nad transkriptom za dano vlogo ('client' ali 'server').
    """
    msg = f"{transcript}:{role}".encode("utf-8")
    return hmac.new(auth_key, msg, hashlib.sha256).hexdigest()


def derive_final_shared_key(
    auth_key: bytes,
    transcript: str
) -> str:
    """
    Izpelje dolgoročni 256-bitni simetrični HMAC ključ iz avtenticiranega transkripta.
    """
    info = b"safeer-companion-v0.8.1-session"
    prk = hmac.new(transcript.encode("utf-8"), auth_key, hashlib.sha256).digest()
    t1 = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
    return t1[:32].hex()


def derive_pairing_key(
    pin: str,
    client_nonce: str,
    server_nonce: str,
    info: str = "safeer-companion-v0.8"
) -> str:
    """
    Izpelje varen 256-bitni (32 bajtov / 64 hex) simetrični ključ z uporabo standardnega
    RFC 5869 HKDF-SHA256 protokola iz 6-mestnega PIN-a in združenih noncov.
    (Ohranjeno za nazaj združljivost z V0.8).
    """
    ikm = pin.strip().encode("utf-8")
    salt = f"{client_nonce}:{server_nonce}".encode("utf-8")
    info_bytes = info.encode("utf-8")

    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    t1 = hmac.new(prk, info_bytes + b"\x01", hashlib.sha256).digest()
    return t1[:32].hex()

