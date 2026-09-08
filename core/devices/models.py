"""
Podatkovni modeli za naprave v Safeer Control.
Omogoča jasno ločitev med omrežnim lokatorjem (Kje je naprava?)
in kriptografsko identiteto naprave (Ali je to res moja naprava?).
"""

from enum import Enum
import uuid
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class DeviceType(str, Enum):
    ANDROID_TV = "android_tv"
    AUDIO_SOUNDBAR = "audio_soundbar"
    ANDROID_PHONE = "android_phone"
    PC = "pc"
    ROUTER = "router"
    DNS_ADBLOCK = "dns_adblock"
    CAST = "cast"
    GENERIC = "generic"


class DeviceStatus(BaseModel):
    online: bool = False
    latency_ms: float = -1.0
    power_on: Optional[bool] = None
    volume: Optional[int] = None
    muted: Optional[bool] = None
    active_app: Optional[str] = None
    extra: Dict[str, Any] = Field(default_factory=dict)


class NetworkLocator(BaseModel):
    """Omrežna lokacija (Kje je naprava?). Dinamično posodobljiva preko mDNS/SSDP/DHCP."""
    host: str
    port: int
    last_resolved_at: Optional[str] = None


class DeviceIdentity(BaseModel):
    """Kriptografska identiteta naprave (Ali je to res moja naprava?)."""
    device_uuid: str = Field(default_factory=lambda: str(uuid.uuid4()))
    trusted: bool = True
    fingerprint: Optional[str] = None
    auth_token_hash: Optional[str] = None


class Device(BaseModel):
    id: str
    name: str
    type: DeviceType
    host: str
    port: int
    enabled: bool = True
    status: DeviceStatus = Field(default_factory=DeviceStatus)
    identity: DeviceIdentity = Field(default_factory=DeviceIdentity)
