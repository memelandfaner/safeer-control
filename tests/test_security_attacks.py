"""
Varnostni regresijski testni paket (Security Attack Suite) za Safeer Control.
Preizkuša napade: ;, &&, |, $(), backticks, newline/CRLF, nevarne sheme,
prekomerne dolžine, Unicode anomalije in dvojno kodiranje.
VSI napadi morajo biti zavrnjeni z DENY na ravni PolicyEngine PRED klicem Providerja.
"""

import pytest
from core.devices.models import Device, DeviceType
from core.actions.models import ActionRequest
from core.security.policy import PolicyEngine
from core.actions.types import DecisionType, RiskClass
from core.actions.engine import ActionEngine
from core.devices.registry import DeviceRegistry
from providers.base import BaseDeviceProvider


class SpyProvider(BaseDeviceProvider):
    """Provider, ki beleži ali je bil klican (noben napadalni klic ne sme priti sem)."""
    def __init__(self, device: Device):
        super().__init__(device)
        self.was_called = False
        self.last_action = None
        self.last_params = None

    def connect(self) -> bool:
        return True

    def disconnect(self) -> None:
        pass

    def get_status(self):
        return None

    def execute_action(self, action: str, params):
        self.was_called = True
        self.last_action = action
        self.last_params = params
        return None


@pytest.fixture
def target_tv():
    return Device(
        id="attack_target_tv",
        name="Security Test TV",
        type=DeviceType.ANDROID_TV,
        host="127.0.0.1",
        port=5555
    )


@pytest.fixture
def target_audio():
    return Device(
        id="attack_target_audio",
        name="Security Test Audio",
        type=DeviceType.AUDIO_SOUNDBAR,
        host="127.0.0.1",
        port=49152
    )


# 1. TESTI ZA LUPINSKO VBRIZGAVANJE (SHELL INJECTION)
@pytest.mark.parametrize("payload", [
    "; reboot",
    "&& rm -rf /",
    "| whoami",
    "$(id)",
    "`id`",
    "hello\nreboot",
    "hello\r\nam start",
    "> /sdcard/exploit",
    "< /dev/zero",
    "$PATH",
    "test & sleep 5",
])
def test_shell_injection_rejected_in_all_string_fields(target_tv, payload):
    # a) type_text
    req_text = ActionRequest(device_id="attack_target_tv", action="type_text", params={"text": payload})
    decision = PolicyEngine.evaluate(req_text, target_tv)
    assert decision.decision == DecisionType.DENY
    assert decision.risk_class == RiskClass.DENY

    # b) search
    req_search = ActionRequest(device_id="attack_target_tv", action="search", params={"query": payload})
    decision = PolicyEngine.evaluate(req_search, target_tv)
    assert decision.decision == DecisionType.DENY
    assert decision.risk_class == RiskClass.DENY

    # c) open_smarttube with query
    req_smarttube = ActionRequest(device_id="attack_target_tv", action="open_smarttube", params={"query": payload})
    decision = PolicyEngine.evaluate(req_smarttube, target_tv)
    assert decision.decision == DecisionType.DENY
    assert decision.risk_class == RiskClass.DENY


# 2. TESTI ZA ZLONAMERNE IN NEDOVOLJENE URL SHEME
@pytest.mark.parametrize("bad_url", [
    "javascript:alert(1)",
    "file:///etc/passwd",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    "intent://com.example.evil/#Intent;scheme=bad;end",
    "content://contacts/people",
    "ftp://ftp.example.com/exploit.bin",
    "gopher://evil.com",
    "smb://192.168.1.5/share",
    "about:blank",
    "chrome://version",
])
def test_malicious_url_schemes_denied(target_tv, bad_url):
    req = ActionRequest(device_id="attack_target_tv", action="open_url", params={"url": bad_url})
    decision = PolicyEngine.evaluate(req, target_tv)
    assert decision.decision == DecisionType.DENY
    assert decision.risk_class == RiskClass.DENY
    assert "shema" in decision.reason.lower() or "nedovoljena" in decision.reason.lower()


# 3. TESTI ZA ZLONAMERNE URL-JE (CRLF, PREKOMERNA DOLŽINA, DVOJNO KODIRANJE)
def test_url_with_crlf_injection(target_tv):
    bad_url = "https://safeer.org/test\r\nreboot"
    req = ActionRequest(device_id="attack_target_tv", action="open_url", params={"url": bad_url})
    decision = PolicyEngine.evaluate(req, target_tv)
    assert decision.decision == DecisionType.DENY
    assert decision.risk_class == RiskClass.DENY


def test_url_with_shell_characters(target_tv):
    bad_url = "https://safeer.org/search?q=1;reboot"
    req = ActionRequest(device_id="attack_target_tv", action="open_url", params={"url": bad_url})
    decision = PolicyEngine.evaluate(req, target_tv)
    assert decision.decision == DecisionType.DENY
    assert decision.risk_class == RiskClass.DENY


def test_url_exceeding_max_length(target_tv):
    huge_url = "https://safeer.org/search?q=" + ("A" * 2500)
    req = ActionRequest(device_id="attack_target_tv", action="open_url", params={"url": huge_url})
    decision = PolicyEngine.evaluate(req, target_tv)
    assert decision.decision == DecisionType.DENY
    assert decision.risk_class == RiskClass.DENY


def test_double_url_encoded_injection(target_tv):
    # %2526 je dvojno kodiran & (% -> %25)
    double_encoded = "https://safeer.org/test?param=%253Breboot"
    req = ActionRequest(device_id="attack_target_tv", action="open_url", params={"url": double_encoded})
    decision = PolicyEngine.evaluate(req, target_tv)
    assert decision.decision == DecisionType.DENY
    assert decision.risk_class == RiskClass.DENY


# 4. TESTI ZA NEDOVOLJENE APLIKACIJE IN PAKETE
@pytest.mark.parametrize("pkg", [
    "com.evil.malware",
    "com.android.settings",
    "org.torproject.android",
    "com.termux",
    "com.google.android.packageinstaller",
    "bad;reboot",
    "",
])
def test_unauthorized_package_names(target_tv, pkg):
    req = ActionRequest(device_id="attack_target_tv", action="launch_app", params={"package": pkg})
    decision = PolicyEngine.evaluate(req, target_tv)
    assert decision.decision == DecisionType.DENY
    assert decision.risk_class == RiskClass.DENY


# 5. TESTI ZA ZLORABO ŠTEVILČNIH PARAMETROV
def test_audio_volume_tampering(target_audio):
    for bad_vol in [-50, 101, 9999, "abc", None]:
        req = ActionRequest(device_id="attack_target_audio", action="set_volume", params={"volume": bad_vol})
        decision = PolicyEngine.evaluate(req, target_audio)
        assert decision.decision == DecisionType.DENY


def test_tv_channel_tampering(target_tv):
    for bad_ch in [-1, 0, 10000, 999999, "invalid"]:
        req = ActionRequest(device_id="attack_target_tv", action="tune_channel", params={"channel": bad_ch})
        decision = PolicyEngine.evaluate(req, target_tv)
        assert decision.decision == DecisionType.DENY


def test_tv_keycode_tampering(target_tv):
    for bad_kc in [-1, 9999, 12345, "kc"]:
        req = ActionRequest(device_id="attack_target_tv", action="key", params={"keycode": bad_kc})
        decision = PolicyEngine.evaluate(req, target_tv)
        assert decision.decision == DecisionType.DENY


def test_tv_switch_input_tampering(target_tv):
    for bad_in in ["hdmi5", "aux", "scart", "pc;reboot", "ps5 && reboot"]:
        req = ActionRequest(device_id="attack_target_tv", action="switch_input", params={"input": bad_in})
        decision = PolicyEngine.evaluate(req, target_tv)
        assert decision.decision == DecisionType.DENY


# 6. ZAGOTOVITEV: NOBEN NAPADALNI ZAHTEVEK NE DOSEŽE PROVIDERJA
def test_attacks_never_reach_provider(target_tv):
    reg = DeviceRegistry()
    spy = SpyProvider(target_tv)
    reg.register(target_tv, spy)

    engine = ActionEngine(registry=reg)

    attacks = [
        ActionRequest(device_id="attack_target_tv", action="open_url", params={"url": "javascript:alert(1)"}),
        ActionRequest(device_id="attack_target_tv", action="type_text", params={"text": "; reboot"}),
        ActionRequest(device_id="attack_target_tv", action="launch_app", params={"package": "com.evil.malware"}),
        ActionRequest(device_id="attack_target_tv", action="key", params={"keycode": 99999}),
        ActionRequest(device_id="attack_target_tv", action="switch_input", params={"input": "hdmi1; reboot"}),
    ]

    for attack_req in attacks:
        res = engine.dispatch(attack_req)
        assert not res.success
        assert "VARNOSTNA BLOKADA" in res.message
        assert spy.was_called is False
