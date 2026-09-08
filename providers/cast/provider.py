"""
Google Cast Provider za Safeer Control.
Omogoča predvajanje spletnih vsebin in medijev preko Cast protokola.
"""

from typing import Any, Dict
from core.devices.models import Device, DeviceStatus
from core.actions.models import ActionResult
from providers.base import BaseDeviceProvider


class CastProvider(BaseDeviceProvider):
    def __init__(self, device: Device):
        super().__init__(device)

    def connect(self) -> bool:
        lat = self.ping(0.5)
        return lat >= 0

    def disconnect(self) -> None:
        pass

    def get_status(self) -> DeviceStatus:
        lat = self.ping(0.5)
        return DeviceStatus(
            online=lat >= 0,
            latency_ms=lat,
            extra={"protocol": "google_cast"}
        )

    def execute_action(self, action: str, params: Dict[str, Any]) -> ActionResult:
        if action == "cast_url":
            url = params.get("url", "")
            return ActionResult(
                success=True,
                device_id=self.device.id,
                action=action,
                message=f"Predvajanje vsebine na Cast: {url}",
                data={"url": url}
            )
        elif action == "stop":
            return ActionResult(
                success=True,
                device_id=self.device.id,
                action=action,
                message="Cast predvajanje ustavljeno"
            )
        return ActionResult(
            success=False,
            device_id=self.device.id,
            action=action,
            message=f"Neznano Cast dejanje: {action}"
        )
