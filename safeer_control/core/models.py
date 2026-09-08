"""
Podatkovni modeli za Safeer Control.
Uporablja standardne Pydantic modele za preverjanje tipov in serijalizacijo v JSON.
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class DeviceType(str, Enum):
    ANDROID_TV = "android_tv"
    AUDIO_SOUNDBAR = "audio_soundbar"
    ANDROID_PHONE = "android_phone"
    PC = "pc"
    ROUTER = "router"
    DNS_ADBLOCK = "dns_adblock"
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


class ActionRequest(BaseModel):
    device_id: str
    action: str
    params: Dict[str, Any] = Field(default_factory=dict)


class ActionResult(BaseModel):
    success: bool
    device_id: str
    action: str
    message: str = ""
    data: Optional[Any] = None
    elapsed_ms: float = 0.0


class SceneStep(BaseModel):
    device_id: str
    action: str
    params: Dict[str, Any] = Field(default_factory=dict)
    delay_after_ms: int = 0


class Scene(BaseModel):
    id: str
    name: str
    description: str = ""
    steps: List[SceneStep] = Field(default_factory=list)
