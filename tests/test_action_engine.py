"""
Enotni testi za ActionEngine in usmerjanje dejanj.
"""

from core.devices.models import Device, DeviceType
from core.actions.models import ActionRequest, ActionResult
from core.devices.registry import DeviceRegistry
from core.actions.engine import ActionEngine
from providers.base import BaseDeviceProvider


class DummyProvider(BaseDeviceProvider):
    def connect(self) -> bool:
        return True

    def disconnect(self) -> None:
        pass

    def get_status(self):
        return None

    def execute_action(self, action: str, params):
        return ActionResult(
            success=True,
            device_id=self.device.id,
            action=action,
            message="Mock izvedba uspela",
            data=params
        )


def test_action_engine_dispatch_success():
    reg = DeviceRegistry()
    dev = Device(
        id="mock_tv",
        name="Mock TV",
        type=DeviceType.ANDROID_TV,
        host="127.0.0.1",
        port=5555
    )
    prov = DummyProvider(dev)
    reg.register(dev, prov)

    engine = ActionEngine(registry=reg)
    req = ActionRequest(
        device_id="mock_tv",
        action="wake"
    )

    res = engine.dispatch(req)
    assert res.success
    assert res.action == "wake"
    assert res.message == "Mock izvedba uspela"


def test_action_engine_rejects_unknown_device():
    reg = DeviceRegistry()
    engine = ActionEngine(registry=reg)
    req = ActionRequest(
        device_id="non_existent_device",
        action="power"
    )

    res = engine.dispatch(req)
    assert not res.success
    assert "ni registrirana" in res.message


def test_action_engine_blocked_by_policy():
    reg = DeviceRegistry()
    dev = Device(
        id="mock_audio",
        name="Mock Audio",
        type=DeviceType.AUDIO_SOUNDBAR,
        host="127.0.0.1",
        port=49152
    )
    prov = DummyProvider(dev)
    reg.register(dev, prov)

    engine = ActionEngine(registry=reg)
    req = ActionRequest(
        device_id="mock_audio",
        action="set_volume",
        params={"volume": 999}
    )

    res = engine.dispatch(req)
    assert not res.success
    assert "VARNOSTNA BLOKADA" in res.message
