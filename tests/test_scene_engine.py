"""
Enotni in integracijski testi za Scene Engine 2.0 (Transakcijska orkestracija).
Preizkuša: Cinema orkestracijo, preflight varnost, retry logiko,
inteligentni stanjem-zavedni rollback in audit correlation ID sledljivost.
"""

import pytest
from typing import Any, Dict
from core.devices.models import Device, DeviceType, DeviceStatus, DeviceIdentity
from core.actions.models import ActionResult
from core.actions.engine import ActionEngine
from core.devices.registry import DeviceRegistry
from core.security.audit import get_audit_logger
from scenes.models import SceneExecutionStatus, SceneExecutionReport
from scenes.engine import SceneEngine
from providers.base import BaseDeviceProvider


class MockTVProvider(BaseDeviceProvider):
    def __init__(self, device: Device, start_online: bool = True, start_power: bool = False):
        super().__init__(device)
        self.is_online = start_online
        self.is_awake = start_power
        self.active_app = "Domači zaslon" if start_power else "V mirovanju"
        self.call_history = []
        self.fail_app_launch = False

    def connect(self) -> bool:
        return self.is_online

    def disconnect(self) -> None:
        pass

    def get_status(self) -> DeviceStatus:
        return DeviceStatus(
            online=self.is_online,
            latency_ms=1.5 if self.is_online else -1.0,
            power_on=self.is_awake,
            active_app=self.active_app
        )

    def execute_action(self, action: str, params: Dict[str, Any]) -> ActionResult:
        self.call_history.append((action, params))
        if not self.is_online:
            return ActionResult(success=False, device_id=self.device.id, action=action, message="TV Offline")

        if action == "wake":
            self.is_awake = True
            self.active_app = "Domači zaslon"
            return ActionResult(success=True, device_id=self.device.id, action=action, message="TV Wakeup")

        elif action == "sleep":
            self.is_awake = False
            self.active_app = "V mirovanju"
            return ActionResult(success=True, device_id=self.device.id, action=action, message="TV Sleep")

        elif action == "open_browser":
            if self.fail_app_launch:
                return ActionResult(success=False, device_id=self.device.id, action=action, message="Crash pri zagonu Safeer Browserja")
            self.active_app = "Safeer Browser"
            return ActionResult(success=True, device_id=self.device.id, action=action, message="Safeer Browser zagnan")

        return ActionResult(success=True, device_id=self.device.id, action=action, message=f"TV {action}")


class MockAudioProvider(BaseDeviceProvider):
    def __init__(self, device: Device, start_online: bool = True, start_volume: int = 25, start_muted: bool = True):
        super().__init__(device)
        self.is_online = start_online
        self.current_volume = start_volume
        self.is_muted = start_muted
        self.call_history = []
        self.fail_attempts_remaining = 0

    def connect(self) -> bool:
        return self.is_online

    def disconnect(self) -> None:
        pass

    def get_status(self) -> DeviceStatus:
        return DeviceStatus(
            online=self.is_online,
            latency_ms=2.0 if self.is_online else -1.0,
            volume=self.current_volume,
            muted=self.is_muted
        )

    def execute_action(self, action: str, params: Dict[str, Any]) -> ActionResult:
        self.call_history.append((action, params))
        if not self.is_online:
            return ActionResult(success=False, device_id=self.device.id, action=action, message="JBL Offline")

        if self.fail_attempts_remaining > 0:
            self.fail_attempts_remaining -= 1
            return ActionResult(success=False, device_id=self.device.id, action=action, message="Začasna omrežna napaka")

        if action == "unmute":
            self.is_muted = False
            return ActionResult(success=True, device_id=self.device.id, action=action, message="JBL Unmuted")

        elif action == "mute":
            self.is_muted = True
            return ActionResult(success=True, device_id=self.device.id, action=action, message="JBL Muted")

        elif action in ("volume", "set_volume"):
            self.current_volume = int(params.get("volume", 20))
            return ActionResult(success=True, device_id=self.device.id, action=action, message=f"JBL Volume {self.current_volume}")

        return ActionResult(success=True, device_id=self.device.id, action=action, message=f"JBL {action}")


@pytest.fixture
def setup_environment():
    reg = DeviceRegistry()

    # TV
    tv_dev = Device(
        id="living_room_tv",
        name="Philips TV",
        type=DeviceType.ANDROID_TV,
        host="127.0.0.1",
        port=5555,
        identity=DeviceIdentity(trusted=True)
    )
    tv_prov = MockTVProvider(tv_dev, start_online=True, start_power=False)
    reg.register(tv_dev, tv_prov)

    # Audio
    audio_dev = Device(
        id="living_room_audio",
        name="JBL Bar 300",
        type=DeviceType.AUDIO_SOUNDBAR,
        host="127.0.0.1",
        port=49152,
        identity=DeviceIdentity(trusted=True)
    )
    audio_prov = MockAudioProvider(audio_dev, start_online=True, start_volume=25, start_muted=True)
    reg.register(audio_dev, audio_prov)

    act_engine = ActionEngine(registry=reg)
    scene_engine = SceneEngine(action_engine=act_engine, registry=reg)

    return scene_engine, tv_prov, audio_prov


def test_cinema_scene_successful_orchestration(setup_environment):
    scene_engine, tv_prov, audio_prov = setup_environment

    # Začetno stanje: TV spi, JBL je utišan na 25 %
    assert tv_prov.is_awake is False
    assert audio_prov.is_muted is True
    assert audio_prov.current_volume == 25

    # Izvedi Cinema sceno
    report = scene_engine.execute_scene("cinema")

    # 1. Preveri status poročila
    assert report.status == SceneExecutionStatus.COMPLETED
    assert report.correlation_id.startswith("tx_scene_cinema_")
    assert len(report.step_results) == 4

    # 2. Preveri končno stanje naprav po verifikaciji
    assert tv_prov.is_awake is True
    assert audio_prov.is_muted is False
    assert audio_prov.current_volume == 45
    assert tv_prov.active_app == "Safeer Browser"


def test_preflight_failure_offline_device(setup_environment):
    scene_engine, tv_prov, audio_prov = setup_environment

    # Simuliraj izpad TV povezave
    tv_prov.is_online = False

    report = scene_engine.execute_scene("cinema")

    # Preflight mora pasti brez izvajanja korakov
    assert report.status == SceneExecutionStatus.FAILED
    assert "ni dosegljiva" in report.error_message
    # JBL ne sme prejeti nobenega ukaza!
    assert len(audio_prov.call_history) == 0


def test_step_retry_then_succeed(setup_environment):
    scene_engine, tv_prov, audio_prov = setup_environment

    # Simuliraj 1 začasni neuspeh pri JBL ukazu (bo ponovil in uspel)
    audio_prov.fail_attempts_remaining = 1

    report = scene_engine.execute_scene("cinema")

    assert report.status == SceneExecutionStatus.COMPLETED
    assert audio_prov.current_volume == 45


def test_intelligent_rollback_on_failure(setup_environment):
    scene_engine, tv_prov, audio_prov = setup_environment

    # Začetno stanje: TV ugasnjen (power_on=False), JBL utišan na 25 %
    assert tv_prov.is_awake is False
    assert audio_prov.is_muted is True
    assert audio_prov.current_volume == 25

    # Nastavi TV tako, da zagon brskalnika (4. korak) odpove
    tv_prov.fail_app_launch = True

    report = scene_engine.execute_scene("cinema")

    # Scena mora odpovedati in izvesti ROLLBACK
    assert report.status == SceneExecutionStatus.ROLLED_BACK
    assert "ni uspel" in report.error_message

    # INTELIGENTNI ROLLBACK PREVERJANJE:
    # 1. Glasnost JBL se mora vrniti na začetnih 25 % (ne na 0 ali 45!)
    assert audio_prov.current_volume == 25

    # 2. JBL se mora znova utišati (muted = True)
    assert audio_prov.is_muted is True

    # 3. TV se mora vrniti v spanje (power_on = False)
    assert tv_prov.is_awake is False


def test_audit_correlation_id_tracing(setup_environment):
    scene_engine, tv_prov, audio_prov = setup_environment
    logger = get_audit_logger()

    report = scene_engine.execute_scene("cinema")
    assert report.status == SceneExecutionStatus.COMPLETED
    cid = report.correlation_id

    # Preveri zapise v revizijskem dnevniku
    recent = logger.get_recent(limit=20)
    matching_records = [r for r in recent if r.get("correlation_id") == cid]

    # Vsaj 4 koraki + zaključno poročilo scene
    assert len(matching_records) >= 5
    for r in matching_records:
        assert r["correlation_id"] == cid
