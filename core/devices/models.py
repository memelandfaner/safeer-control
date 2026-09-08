"""
Podatkovni modeli za naprave v Safeer Control V0.4 (Dynamic Device Discovery).
Uveljavlja temeljno načelo: device_id != IP address.
Jasna ločitev:
- Omrežni lokator (host/port/discovery_method) -> Kje je naprava?
- Kriptografska identiteta (UUID/fingerprint/trust_state) -> Ali je to res moja naprava?
"""

import time
import uuid
from enum import Enum
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


class DiscoveryMethod(str, Enum):
    MDNS = "mdns"
    ADB_PROBE = "adb_probe"
    SSDP = "ssdp"
    STATIC_FALLBACK = "static_fallback"


class TrustState(str, Enum):
    TRUSTED = "trusted"
    UNPAIRED = "unpaired"
    REVOKED = "revoked"


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
    last_resolved_at: float = Field(default_factory=time.time)
    discovery_method: DiscoveryMethod = DiscoveryMethod.STATIC_FALLBACK


class DeviceIdentity(BaseModel):
    """Kriptografska identiteta naprave (Ali je to res moja naprava?)."""
    device_uuid: str = Field(default_factory=lambda: str(uuid.uuid4()))
    trusted: bool = True
    fingerprint: Optional[str] = None
    auth_token_hash: Optional[str] = None
    trust_state: TrustState = TrustState.TRUSTED


class Device(BaseModel):
    id: str
    name: str
    type: DeviceType
    host: str
    port: int
    enabled: bool = True
    status: DeviceStatus = Field(default_factory=DeviceStatus)
    identity: DeviceIdentity = Field(default_factory=DeviceIdentity)
    discovery_method: str = "static_fallback"
    last_seen: float = Field(default_factory=time.time)
    trust_state: str = "trusted"

    def update_locator(self, new_host: str, new_port: int, method: str) -> None:
        """Posodobi izključno lokator naprave, brez samodejnega spreminjanja identitete."""
        self.host = new_host
        self.port = new_port
        self.discovery_method = method
        self.last_seen = time.time()
