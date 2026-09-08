"""
Android Phone Provider za Safeer Control.
Upravljanje funkcij telefona v običajnem načinu.
"""

from typing import Any, Dict
from core.devices.models import Device, DeviceStatus
from core.actions.models import ActionResult
from providers.base import BaseDeviceProvider


class AndroidProvider(BaseDeviceProvider):
    def __init__(self, device: Device):
        super().__init__(device)

    def connect(self) -> bool:
        return True

    def disconnect(self) -> None:
        pass

    def get_status(self) -> DeviceStatus:
        lat = self.ping(0.5)
        return DeviceStatus(
            online=lat >= 0 or self.device.host in ("127.0.0.1", "localhost"),
            latency_ms=lat if lat >= 0 else 0.0,
            extra={"mode": "normal", "platform": "android"}
        )

    def execute_action(self, action: str, params: Dict[str, Any]) -> ActionResult:
        if action == "status":
            return ActionResult(
                success=True,
                device_id=self.device.id,
                action=action,
                message="Telefon je aktiven",
                data=self.get_status().model_dump()
            )
        return ActionResult(
            success=False,
            device_id=self.device.id,
            action=action,
            message=f"Dejanje '{action}' ni podprto v običajnem načinu."
        )
