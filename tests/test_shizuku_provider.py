"""
Varnostni in enotni testi za Safeer Control V0.5.1 (Real Shizuku Boundary).
Preverja:
1. ShizukuProvider sploh nima uvoza subprocess, adb ali os (ničelno zanašanje na adb shell!).
2. ShizukuProvider v javnem contractu nima exec, shell, su, argv ali posplošenih metod.
3. Tipiziran CompanionTransport protokol s strogim fail-closed obnašanjem.
4. CapabilityGate uveljavlja stroge varnostne meje (zaščiteni sistemski paketi, dovoljene nastavitve).
5. Poskusi vbrizgavanja ukazov ali klicanja nedovoljenih akcij se takoj zavrnejo (DENY).
6. Celotna veriga (Action -> PolicyEngine -> CapabilityGate -> ShizukuProvider -> CompanionTransport -> AuditTrail).
"""

import pytest
from unittest.mock import patch, MagicMock
from typing import Dict, Any

from core.devices.models import Device, DeviceType, DeviceIdentity
from core.actions.models import ActionRequest, ActionResult
from core.actions.types import RiskClass, DecisionType
from core.actions.engine import ActionEngine
from core.devices.registry import DeviceRegistry
from core.security.policy import PolicyEngine
from core.security.audit import get_audit_logger
from providers.shizuku.provider import ShizukuProvider
from providers.shizuku.capabilities import (
    Capability,
    CapabilityGate,
    ALLOWED_MAINTENANCE_PACKAGES,
    PROTECTED_SYSTEM_PACKAGES,
    ALLOWED_SETTING_KEYS
)
from providers.shizuku.transport import (
    BaseCompanionTransport,
    HttpCompanionTransport,
    CompanionRequest,
    CompanionResponse,
)


def test_shizuku_provider_source_code_has_no_subprocess_or_adb():
    """
    KLJUČNI TEST ZA V0.5.1 (Real Shizuku Boundary):
    V kodi modula providers.shizuku.provider ne sme biti uvožen ali uporabljen subprocess ali adb!
    """
    import providers.shizuku.provider as prov_mod
    with open(prov_mod.__file__, "r", encoding="utf-8") as f:
        src = f.read()

    assert "import subprocess" not in src, "ShizukuProvider ne sme uvažati subprocess!"
    assert "subprocess.run" not in src, "ShizukuProvider ne sme klicati subprocess.run()!"
    assert "import os" not in src, "ShizukuProvider ne sme uvažati os!"
    assert "os.system" not in src, "ShizukuProvider ne sme klicati os.system()!"
    assert "adb" not in src.lower(), "ShizukuProvider ne sme vsebovati hardkodiranih adb ukazov!"


def test_shizuku_provider_contract_has_no_generic_shell_or_exec():
    """
    ShizukuProvider v svoji javni pogodbi nima NOBENEGA posplošenega načina za izvajanje ukazov.
    Ne obstajajo exec, shell, su, run_command, argv ali podobni escape hatchi.
    """
    dev = Device(
        id="shizuku_test",
        name="Shizuku Test",
        type=DeviceType.SHIZUKU,
        host="192.168.1.50",
        port=8995
    )
    prov = ShizukuProvider(dev)

    # 1. Preveri odsotnost nevarnih metod
    assert not hasattr(prov, "exec"), "ShizukuProvider NE SME imeti metode exec()"
    assert not hasattr(prov, "shell"), "ShizukuProvider NE SME imeti metode shell()"
    assert not hasattr(prov, "su"), "ShizukuProvider NE SME imeti metode su()"
    assert not hasattr(prov, "run_command"), "ShizukuProvider NE SME imeti metode run_command()"
    assert not hasattr(prov, "raw_cmd"), "ShizukuProvider NE SME imeti metode raw_cmd()"

    # 2. Preveri, da obstajajo izključno tipizirane zmožnosti
    assert hasattr(prov, "force_stop")
    assert hasattr(prov, "read_setting")
    assert hasattr(prov, "clear_cache")


def test_http_companion_transport_fail_closed_on_error():
    """Transport mora ob omrežni ali HTTP napaki delovati strogo fail-closed."""
    transport = HttpCompanionTransport(host="192.168.1.250", port=8995, timeout=0.1)
    req = CompanionRequest(
        capability=Capability.APP_FORCE_STOP,
        params={"package": "com.example.safeerbrowser"}
    )

    # Nedosegljiv gostitelj -> fail-closed (success=False)
    resp = transport.send(req)
    assert resp.success is False
    assert "Fail-closed" in resp.error_message
    assert resp.capability == Capability.APP_FORCE_STOP.value


def test_capability_gate_denies_arbitrary_shell_and_protected_packages():
    """Preveri, da CapabilityGate takoj blokira poskuse zlorabe."""
    # 1. Poskus podtikanja shell ukazov
    ok, reason = CapabilityGate.require(Capability.APP_FORCE_STOP, {
        "package": "com.example.safeerbrowser",
        "exec": "rm -rf /"
    })
    assert ok is False
    assert "Varnostna kršitev" in reason

    ok, reason = CapabilityGate.require(Capability.APP_FORCE_STOP, {
        "package": "com.example.safeerbrowser",
        "su": "reboot"
    })
    assert ok is False

    # 2. Poskus zaustavitve zaščitenega sistemskega paketa
    for sys_pkg in ("com.android.systemui", "android", "com.google.android.gms", "com.android.settings"):
        ok, reason = CapabilityGate.require(Capability.APP_FORCE_STOP, {"package": sys_pkg})
        assert ok is False
        assert "prepovedana" in reason or "zaščitenega" in reason

    # 3. Neznana aplikacija, ki ni na beli listi
    ok, reason = CapabilityGate.require(Capability.APP_FORCE_STOP, {"package": "com.hacker.exploit"})
    assert ok is False
    assert "ni na seznamu" in reason


def test_capability_gate_allows_whitelisted_operations():
    """Preveri, da CapabilityGate odobri veljavne operacije."""
    # 1. Odobren force-stop
    ok, reason = CapabilityGate.require(Capability.APP_FORCE_STOP, {"package": "com.example.safeerbrowser"})
    assert ok is True
    assert reason == "Odobreno"

    # 2. Odobreno branje sistemske nastavitve
    ok, reason = CapabilityGate.require(Capability.SETTINGS_READ, {
        "namespace": "global",
        "key": "stay_on_while_plugged_in"
    })
    assert ok is True

    # 3. Poskus branja neavtorizirane nastavitve (npr. gesla/PIN)
    ok, reason = CapabilityGate.require(Capability.SETTINGS_READ, {
        "namespace": "secure",
        "key": "wifi_password"
    })
    assert ok is False
    assert "ni na seznamu" in reason


def test_policy_engine_rejects_unauthorized_actions_on_shizuku():
    """PolicyEngine mora avtomatsko zavrniti poljubne akcije, kot so 'exec', 'reboot' ipd."""
    dev = Device(
        id="shizuku_companion",
        name="Companion",
        type=DeviceType.SHIZUKU,
        host="192.168.1.50",
        port=8995
    )

    # 1. Poskus klica nedovoljene akcije 'exec'
    req = ActionRequest(device_id=dev.id, action="exec", params={"command": "id"})
    decision = PolicyEngine.evaluate(req, dev)
    assert decision.decision == DecisionType.DENY
    assert decision.risk_class == RiskClass.DENY
    assert "ni dovoljeno" in decision.reason

    # 2. Poskus vbrizgavanja shell metaznakov v paket
    req_bad_pkg = ActionRequest(
        device_id=dev.id,
        action="app_force_stop",
        params={"package": "com.example.safeerbrowser; reboot"}
    )
    decision = PolicyEngine.evaluate(req_bad_pkg, dev)
    assert decision.decision == DecisionType.DENY
    assert decision.risk_class == RiskClass.DENY


class MockCompanionTransport(BaseCompanionTransport):
    """Testni mock za simulacijo Companion komunikacije brez zunanjega omrežja."""

    def __init__(self, should_succeed: bool = True):
        self.should_succeed = should_succeed
        self.last_request = None

    def send(self, request: CompanionRequest) -> CompanionResponse:
        self.last_request = request
        if self.should_succeed:
            return CompanionResponse(
                request_id=request.request_id,
                capability=request.capability.value,
                success=True,
                data={"result": "ok", **request.params}
            )
        return CompanionResponse(
            request_id=request.request_id,
            capability=request.capability.value,
            success=False,
            error_message="Fail-closed: Companion napaka"
        )

    def check_health(self) -> bool:
        return self.should_succeed


def test_action_engine_end_to_end_force_stop_with_transport_and_audit():
    """
    Celoten preizkus izvedbe skozi ActionEngine:
    Action -> PolicyEngine (CONFIRM) -> User Confirm -> CapabilityGate -> ShizukuProvider.force_stop -> CompanionTransport -> AuditTrail
    """
    reg = DeviceRegistry()
    dev = Device(
        id="shizuku_test_dev",
        name="Shizuku Companion",
        type=DeviceType.SHIZUKU,
        host="192.168.1.50",
        port=8995,
        identity=DeviceIdentity(trusted=True)
    )
    mock_transport = MockCompanionTransport(should_succeed=True)
    prov = ShizukuProvider(dev, transport=mock_transport)
    reg.register(dev, prov)

    engine = ActionEngine(registry=reg)

    # 1. Poskus brez potrditve (CONFIRM -> zavrnjeno s REQUIRE_CONFIRMATION)
    req = ActionRequest(
        device_id="shizuku_test_dev",
        action="app_force_stop",
        params={"package": "com.example.safeerbrowser"}
    )
    res_unconf = engine.dispatch(req)
    assert res_unconf.success is False
    assert "POTREBNA POTRDITEV" in res_unconf.message

    # 2. Izvedba s potrditvijo
    res_ok = engine.dispatch(req, trust_context={"confirmed": True})

    assert res_ok.success is True
    assert "uspešno ustavljena" in res_ok.message
    assert res_ok.action_id == req.action_id

    # Preveri, da je transport prejel točno strukturirano zahtevo
    assert mock_transport.last_request is not None
    assert mock_transport.last_request.capability == Capability.APP_FORCE_STOP
    assert mock_transport.last_request.params == {"package": "com.example.safeerbrowser"}

    # 3. Preveri Audit Trail
    audit_logger = get_audit_logger()
    records = list(audit_logger._buffer)
    matched = [r for r in records if r.action_id == req.action_id and r.success is True]
    assert len(matched) == 1
    rec = matched[0]
    assert rec.capability == Capability.APP_FORCE_STOP.value
    assert rec.device_id == "shizuku_test_dev"
    assert rec.action == "app_force_stop"
    assert rec.decision == DecisionType.ALLOW


def test_action_engine_end_to_end_settings_read_with_transport():
    """Preveri varno branje nastavitve skozi tipiziran Companion transport."""
    reg = DeviceRegistry()
    dev = Device(
        id="shizuku_test_dev2",
        name="Shizuku Companion",
        type=DeviceType.SHIZUKU,
        host="192.168.1.50",
        port=8995,
        identity=DeviceIdentity(trusted=True)
    )
    mock_transport = MockCompanionTransport(should_succeed=True)
    prov = ShizukuProvider(dev, transport=mock_transport)
    reg.register(dev, prov)

    engine = ActionEngine(registry=reg)

    req = ActionRequest(
        device_id="shizuku_test_dev2",
        action="settings_read",
        params={"namespace": "global", "key": "stay_on_while_plugged_in"}
    )

    res = engine.dispatch(req)
    assert res.success is True
    assert mock_transport.last_request.capability == Capability.SETTINGS_READ
    assert mock_transport.last_request.params == {"namespace": "global", "key": "stay_on_while_plugged_in"}


def test_action_engine_fail_closed_when_companion_fails():
    """Preveri fail-closed vedenje celotnega ActionEngine ob odpovedi Companiona."""
    reg = DeviceRegistry()
    dev = Device(
        id="shizuku_test_dev3",
        name="Shizuku Companion",
        type=DeviceType.SHIZUKU,
        host="192.168.1.50",
        port=8995,
        identity=DeviceIdentity(trusted=True)
    )
    mock_transport = MockCompanionTransport(should_succeed=False)
    prov = ShizukuProvider(dev, transport=mock_transport)
    reg.register(dev, prov)

    engine = ActionEngine(registry=reg)

    req = ActionRequest(
        device_id="shizuku_test_dev3",
        action="app_force_stop",
        params={"package": "com.example.safeerbrowser"}
    )
    res = engine.dispatch(req, trust_context={"confirmed": True})
    assert res.success is False
    assert "Fail-closed" in res.message


def test_direct_provider_execute_action_blocks_unauthorized_commands():
    """Tudi če bi klic neposredno dosegel provider, provider zavrne katerokoli ne-tipizirano dejanje."""
    dev = Device(id="shizuku_dev4", name="C", type=DeviceType.SHIZUKU, host="127.0.0.1", port=0)
    prov = ShizukuProvider(dev)

    res = prov.execute_action("exec", {"command": "ls -la"})
    assert res.success is False
    assert "prepovedani" in res.message or "ni podprto" in res.message
