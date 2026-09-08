"""
Enotni testi za UPnPProvider (JBL Bar 300 UPnP / SOAP).
Testira hardware-aware obnašanje (brez nepotrebnih unmute klicev ob aktivnem zvoku).
"""

from unittest.mock import patch, MagicMock
from core.devices.models import Device, DeviceType, DeviceStatus
from providers.upnp.provider import UPnPProvider


def test_upnp_provider_unmute_when_already_active():
    """Če je zvočnik že aktiven, unmute ne sme pošiljati SOAP zahteve (zaščita HDMI-CEC)."""
    dev = Device(
        id="jbl_test",
        name="JBL Test",
        type=DeviceType.AUDIO_SOUNDBAR,
        host="127.0.0.1",
        port=49152
    )
    provider = UPnPProvider(dev)

    # Mock get_status vrača muted=False
    mock_status = DeviceStatus(online=True, latency_ms=1.0, volume=35, muted=False)
    with patch.object(provider, "get_status", return_value=mock_status):
        with patch.object(provider, "_soap_request") as mock_soap:
            res = provider.execute_action("unmute", {})
            assert res.success
            assert "že aktiven" in res.message
            # Zagotovi, da se SOAP zahteva ni poslala!
            mock_soap.assert_not_called()


def test_upnp_provider_unmute_when_muted():
    """Če je zvočnik utišan, mora poslati SetMute(0)."""
    dev = Device(
        id="jbl_test",
        name="JBL Test",
        type=DeviceType.AUDIO_SOUNDBAR,
        host="127.0.0.1",
        port=49152
    )
    provider = UPnPProvider(dev)

    mock_status = DeviceStatus(online=True, latency_ms=1.0, volume=35, muted=True)
    with patch.object(provider, "get_status", return_value=mock_status):
        with patch.object(provider, "_soap_request", return_value="<SetMuteResponse/>") as mock_soap:
            res = provider.execute_action("unmute", {})
            assert res.success
            assert "unmute" in res.message
            mock_soap.assert_called_once()
            args, _ = mock_soap.call_args
            assert args[0] == "SetMute"
            assert "<DesiredMute>0</DesiredMute>" in args[1]


def test_upnp_provider_set_volume():
    """Testira pravilno pošiljanje ukaza SetVolume."""
    dev = Device(
        id="jbl_test",
        name="JBL Test",
        type=DeviceType.AUDIO_SOUNDBAR,
        host="127.0.0.1",
        port=49152
    )
    provider = UPnPProvider(dev)

    with patch.object(provider, "_soap_request", return_value="<SetVolumeResponse/>") as mock_soap:
        res = provider.execute_action("set_volume", {"volume": 42})
        assert res.success
        assert res.data["volume"] == 42
        mock_soap.assert_called_once()
        args, _ = mock_soap.call_args
        assert args[0] == "SetVolume"
        assert "<DesiredVolume>42</DesiredVolume>" in args[1]


def test_upnp_provider_volume_step():
    """Testira povečanje in zmanjšanje glasnosti za korak."""
    dev = Device(
        id="jbl_test",
        name="JBL Test",
        type=DeviceType.AUDIO_SOUNDBAR,
        host="127.0.0.1",
        port=49152
    )
    provider = UPnPProvider(dev)

    mock_status = DeviceStatus(online=True, latency_ms=1.0, volume=30, muted=False)
    with patch.object(provider, "get_status", return_value=mock_status):
        with patch.object(provider, "_soap_request", return_value="<SetVolumeResponse/>") as mock_soap:
            # Volume up za 5
            res_up = provider.execute_action("volume_up", {"step": 5})
            assert res_up.success
            assert res_up.data["volume"] == 35

            # Volume down za 5
            res_down = provider.execute_action("volume_down", {"step": 5})
            assert res_down.success
            assert res_down.data["volume"] == 25
