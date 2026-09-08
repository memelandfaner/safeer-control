"""
Sprejemni in enotni testi za Safeer Control V0.4 (Dynamic Device Discovery).
Preizkuša:
1. Sprejemni test: simulirana DHCP sprememba IP-ja TV-ja in JBL-a brez spreminjanja .env.
2. Zanesljivo ponovno odkrivanje (SSDP XML in ADB fingerprint verifikacija).
3. Pravilo zaupanja: nov IP NIKOLI samodejno ne podeduje trusted=True, če identiteta ne ustreza!
4. Uspešna izvedba Cinema orkestracije po premiku naprav na nove IP naslove.
"""

import pytest
from unittest.mock import patch, MagicMock
from typing import Dict, Any, Optional

from core.devices.models import Device, DeviceType, DeviceStatus, DeviceIdentity
from core.devices.discovery import SSDPDiscovery, DynamicDiscoveryManager
from core.devices.registry import DeviceRegistry
from core.actions.engine import ActionEngine
from scenes.engine import SceneEngine
from scenes.models import SceneExecutionStatus
from providers.base import BaseDeviceProvider


SAMPLE_UPNP_XML = """<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion>
    <major>1</major>
    <minor>0</minor>
  </specVersion>
  <device>
    <deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType>
    <friendlyName>JBL Bar 300</friendlyName>
    <manufacturer>Harman Kardon</manufacturer>
    <UDN>uuid:2b74052f-13d8-4f81-8b3e-e380f589d891</UDN>
    <serviceList>
      <service>
        <serviceType>urn:schemas-upnp-org:service:RenderingControl:1</serviceType>
        <serviceId>urn:upnp-org:serviceId:RenderingControl</serviceId>
        <controlURL>/upnp/control/dyn_rendering_ctrl</controlURL>
        <eventSubURL>/upnp/event/RenderingControl1</eventSubURL>
        <SCPDURL>/RenderingControl_scpd.xml</SCPDURL>
      </service>
      <service>
        <serviceType>urn:schemas-upnp-org:service:AVTransport:1</serviceType>
        <serviceId>urn:upnp-org:serviceId:AVTransport</serviceId>
        <controlURL>/upnp/control/AVTransport1</controlURL>
      </service>
    </serviceList>
  </device>
</root>"""


def test_ssdp_xml_parsing_extracts_control_url():
    mock_resp = MagicMock()
    mock_resp.read.return_value = SAMPLE_UPNP_XML.encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        info = SSDPDiscovery.parse_description_xml("http://192.168.1.151:49152/description.xml")

    assert info is not None
    assert info["friendly_name"] == "JBL Bar 300"
    assert info["control_url"] == "http://192.168.1.151:49152/upnp/control/dyn_rendering_ctrl"
    assert info["host"] == "192.168.1.151"
    assert info["port"] == 49152


class DynamicSimulatedTV(BaseDeviceProvider):
    def __init__(self, device: Device, serial: str):
        super().__init__(device)
        self.serial = serial
        self.is_awake = False
        self.active_app = "V mirovanju"
        self.current_ip = device.host

    def connect(self) -> bool:
        return True

    def disconnect(self) -> None:
        pass

    def update_target(self, new_host: str, new_port: int) -> None:
        self.device.host = new_host
        self.device.port = new_port
        self.current_ip = new_host

    def get_status(self) -> DeviceStatus:
        # Če je naprava še vedno na starem ugasnjenem IP-ju, je nedosegljiva
        if self.current_ip != self.device.host:
            return DeviceStatus(online=False, latency_ms=-1.0)
        return DeviceStatus(
            online=True,
            latency_ms=1.2,
            power_on=self.is_awake,
            active_app=self.active_app
        )

    def execute_action(self, action: str, params: Dict[str, Any]):
        from core.actions.models import ActionResult
        if action == "wake":
            self.is_awake = True
            self.active_app = "Domači zaslon"
            return ActionResult(success=True, device_id=self.device.id, action=action, message="TV Wake")
        elif action == "open_browser":
            self.active_app = "Safeer Browser"
            return ActionResult(success=True, device_id=self.device.id, action=action, message="Safeer Browser Odprt")
        return ActionResult(success=True, device_id=self.device.id, action=action, message="OK")


class DynamicSimulatedJBL(BaseDeviceProvider):
    def __init__(self, device: Device):
        super().__init__(device)
        self.current_volume = 20
        self.is_muted = True
        self.current_ip = device.host
        self.control_url = f"http://{device.host}:{device.port}/upnp/control/rendercontrol1"

    def connect(self) -> bool:
        return True

    def disconnect(self) -> None:
        pass

    def update_target(self, new_host: str, new_port: int, control_url: Optional[str] = None) -> None:
        self.device.host = new_host
        self.device.port = new_port
        self.current_ip = new_host
        self.control_url = control_url or f"http://{new_host}:{new_port}/dyn"

    def get_status(self) -> DeviceStatus:
        if self.current_ip != self.device.host:
            return DeviceStatus(online=False, latency_ms=-1.0)
        return DeviceStatus(
            online=True,
            latency_ms=1.8,
            volume=self.current_volume,
            muted=self.is_muted
        )

    def execute_action(self, action: str, params: Dict[str, Any]):
        from core.actions.models import ActionResult
        if action == "unmute":
            self.is_muted = False
            return ActionResult(success=True, device_id=self.device.id, action=action, message="Unmute OK")
        elif action in ("volume", "set_volume"):
            self.current_volume = int(params.get("volume", 20))
            return ActionResult(success=True, device_id=self.device.id, action=action, message=f"Vol {self.current_volume}")
        return ActionResult(success=True, device_id=self.device.id, action=action, message="OK")


def test_acceptance_dhcp_ip_change_without_touching_env():
    """
    KLJUČNI SPREJEMNI TEST ZA V0.4:
    1. TV registriran na začetnem IP 192.168.1.100
    2. JBL registriran na začetnem IP 192.168.1.101
    3. DHCP premakne TV na 192.168.1.150 in JBL na 192.168.1.151
    4. Safeer Control brez menjave .env ponovno najde napravi, ohrani pravilno identiteto in izvede Cinema sceno!
    """
    reg = DeviceRegistry()

    # Začetna registracija (stari IP-ji)
    tv_dev = Device(
        id="living_room_tv",
        name="Philips TV",
        type=DeviceType.ANDROID_TV,
        host="192.168.1.100",
        port=5555,
        identity=DeviceIdentity(fingerprint="PHILIPS-SERIAL-8507", trusted=True)
    )
    tv_prov = DynamicSimulatedTV(tv_dev, serial="PHILIPS-SERIAL-8507")
    reg.register(tv_dev, tv_prov)

    audio_dev = Device(
        id="living_room_audio",
        name="JBL Bar 300",
        type=DeviceType.AUDIO_SOUNDBAR,
        host="192.168.1.101",
        port=49152,
        identity=DeviceIdentity(device_uuid="jbl-bar-uuid", trusted=True)
    )
    audio_prov = DynamicSimulatedJBL(audio_dev)
    reg.register(audio_dev, audio_prov)

    # SIMULACIJA DHCP PREMIKA:
    # Fizični TV se je preselil na 192.168.1.150, stari IP 192.168.1.100 ne odgovarja več
    tv_prov.current_ip = "192.168.1.150"
    audio_prov.current_ip = "192.168.1.151"

    # Mockamo omrežno odkrivanje: kandidat 192.168.1.150 ima pravilen TV serial, 192.168.1.151 vrne JBL opis
    def mock_resolve_device(device, candidate_hosts=None):
        if device.type == DeviceType.ANDROID_TV:
            return True, "adb_probe", {"host": "192.168.1.150", "port": 5555, "fingerprint": "PHILIPS-SERIAL-8507"}
        elif device.type == DeviceType.AUDIO_SOUNDBAR:
            return True, "ssdp", {
                "host": "192.168.1.151",
                "port": 49152,
                "control_url": "http://192.168.1.151:49152/upnp/control/dyn_rendering_ctrl"
            }
        return False, "static_fallback", None

    with patch.object(reg.discovery_manager, "resolve_device", side_effect=mock_resolve_device):
        # 1. Poskus osvežitve sproži samodejno re-resolucijo obeh naprav
        stat_tv = reg.refresh_status("living_room_tv")
        stat_audio = reg.refresh_status("living_room_audio")

        # 2. Preveri posodobljene omrežne lokatorje
        assert tv_dev.host == "192.168.1.150"
        assert tv_prov.device.host == "192.168.1.150"
        assert stat_tv.online is True

        assert audio_dev.host == "192.168.1.151"
        assert audio_prov.device.host == "192.168.1.151"
        assert audio_prov.control_url == "http://192.168.1.151:49152/upnp/control/dyn_rendering_ctrl"
        assert stat_audio.online is True

        # 3. Kriptografska identiteta in zaupanje sta OHRANJENA
        assert tv_dev.identity.trusted is True
        assert audio_dev.identity.trusted is True

        # 4. ZAGON CINEMA SCENE — mora v celoti uspeti (COMPLETED) na novih IP-jih!
        act_engine = ActionEngine(registry=reg)
        scene_engine = SceneEngine(action_engine=act_engine, registry=reg)

        report = scene_engine.execute_scene("cinema")
        assert report.status == SceneExecutionStatus.COMPLETED
        assert len(report.step_results) == 4
        assert tv_prov.is_awake is True
        assert audio_prov.is_muted is False
        assert audio_prov.current_volume == 45
        assert tv_prov.active_app == "Safeer Browser"


def test_rogue_device_on_new_ip_never_inherits_trusted():
    """
    Varnostno pravilo V0.4:
    Tujec / nepoverjena naprava na novem IP-ju z napačno identiteto NE SME podedovati zaupanja!
    """
    reg = DeviceRegistry()

    tv_dev = Device(
        id="living_room_tv",
        name="Philips TV",
        type=DeviceType.ANDROID_TV,
        host="192.168.1.100",
        port=5555,
        identity=DeviceIdentity(fingerprint="PHILIPS-ORIGINAL-SERIAL", trusted=True)
    )
    tv_prov = DynamicSimulatedTV(tv_dev, serial="PHILIPS-ORIGINAL-SERIAL")
    reg.register(tv_dev, tv_prov)

    # Stari IP odpove
    tv_prov.current_ip = "192.168.1.150"

    # Na novem IP-ju se javi neznana/zlonamerna naprava z napačnim serialom
    def mock_resolve_rogue(device, candidate_hosts=None):
        # Napačen fingerprint -> zavrnitev
        return False, "adb_probe", None

    with patch.object(reg.discovery_manager, "resolve_device", side_effect=mock_resolve_rogue):
        stat = reg.refresh_status("living_room_tv")
        # Lokator se NE sme posodobiti na nepoverjeno napravo
        assert tv_dev.host == "192.168.1.100"
        assert stat.online is False
