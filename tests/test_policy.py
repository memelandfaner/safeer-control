"""
Enotni testi za PolicyEngine (Varnostni filter).
"""

import pytest
from core.devices.models import Device, DeviceType
from core.actions.models import ActionRequest
from core.security.policy import PolicyEngine


@pytest.fixture
def tv_device():
    return Device(
        id="test_tv",
        name="Test TV",
        type=DeviceType.ANDROID_TV,
        host="127.0.0.1",
        port=5555
    )


@pytest.fixture
def audio_device():
    return Device(
        id="test_audio",
        name="Test JBL",
        type=DeviceType.AUDIO_SOUNDBAR,
        host="127.0.0.1",
        port=49152
    )


def test_reject_arbitrary_shell(tv_device):
    req = ActionRequest(
        device_id="test_tv",
        action="shell",
        params={"cmd": "rm -rf /"}
    )
    allowed, reason, _ = PolicyEngine.validate(req, tv_device)
    assert not allowed
    assert "ni dovoljeno" in reason


def test_reject_command_injection(tv_device):
    req = ActionRequest(
        device_id="test_tv",
        action="type_text",
        params={"text": "hello; reboot"}
    )
    allowed, reason, _ = PolicyEngine.validate(req, tv_device)
    assert not allowed
    assert "prepovedane varnostne znake" in reason


def test_validate_safe_url(tv_device):
    safe_req = ActionRequest(
        device_id="test_tv",
        action="open_url",
        params={"url": "https://www.youtube.com"}
    )
    allowed, _, sanitized = PolicyEngine.validate(safe_req, tv_device)
    assert allowed
    assert sanitized.params["url"] == "https://www.youtube.com"

    bad_req = ActionRequest(
        device_id="test_tv",
        action="open_url",
        params={"url": "javascript:alert(1)"}
    )
    allowed, reason, _ = PolicyEngine.validate(bad_req, tv_device)
    assert not allowed
    assert "Nedovoljena URL shema" in reason


def test_audio_volume_bounds(audio_device):
    req_ok = ActionRequest(device_id="test_audio", action="set_volume", params={"volume": 50})
    allowed, _, sanitized = PolicyEngine.validate(req_ok, audio_device)
    assert allowed
    assert sanitized.params["volume"] == 50

    req_low = ActionRequest(device_id="test_audio", action="set_volume", params={"volume": -10})
    allowed, reason, _ = PolicyEngine.validate(req_low, audio_device)
    assert not allowed
    assert "med 0 in 100" in reason

    req_high = ActionRequest(device_id="test_audio", action="set_volume", params={"volume": 120})
    allowed, reason, _ = PolicyEngine.validate(req_high, audio_device)
    assert not allowed
    assert "med 0 in 100" in reason


def test_reject_unauthorized_package(tv_device):
    req = ActionRequest(
        device_id="test_tv",
        action="launch_app",
        params={"package": "com.dangerous.malware"}
    )
    allowed, reason, _ = PolicyEngine.validate(req, tv_device)
    assert not allowed
    assert "ni na seznamu dovoljenih" in reason
