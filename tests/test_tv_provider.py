"""
Enotni testi za AndroidTVProvider (ADB mock).
"""

from unittest.mock import patch, MagicMock
from safeer_control.core.models import Device, DeviceType
from safeer_control.providers.tv import AndroidTVProvider


def test_tv_provider_actions():
    dev = Device(
        id="tv_unit",
        name="Unit TV",
        type=DeviceType.ANDROID_TV,
        host="127.0.0.1",
        port=5555
    )
    provider = AndroidTVProvider(dev)

    with patch.object(provider, "_adb", return_value="mocked output") as mock_adb:
        # Power toggle
        res = provider.execute_action("power", {})
        assert res.success
        assert res.action == "power"
        mock_adb.assert_called_with(["shell", "input", "keyevent", "26"])

        # Wake
        res = provider.execute_action("wake", {})
        assert res.success
        assert res.action == "wake"
        mock_adb.assert_called_with(["shell", "input", "keyevent", "224"])

        # Open URL
        res = provider.execute_action("open_url", {"url": "https://example.com"})
        assert res.success
        mock_adb.assert_called_with(["shell", "am", "start", "-n", "com.example.safeerbrowser/.MainActivity", "-d", "https://example.com"])

        # Seek
        res = provider.execute_action("seek", {"seconds": 30})
        assert res.success
        mock_adb.assert_called_with(["shell", "am", "broadcast", "-a", "com.example.safeerbrowser.ACTION_SEEK", "--ei", "seconds", "30"])
