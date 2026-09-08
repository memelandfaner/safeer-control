"""
Podatkovni modeli za naprave v Safeer Control.
"""

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


class DeviceStatus(BaseModel):
    online: bool = False
    latency_ms: float = -1.0
    power_on: Optional[bool] = None
    volume: Optional[int] = None
    muted: Optional[bool] = None
    active_app: Optional[str] = None
    extra: Dict[str, Any] = Field(default_factory=dict)


class Device(BaseModel):
    id: str
    name: str
    type: DeviceType
    host: str
    port: int
    enabled: bool = True
    status: DeviceStatus = Field(default_factory=DeviceStatus)
