"""
Varnostni Policy Engine za Safeer Control.
Izvaja strogo validacijo sheme (Pydantic), semantično preverjanje,
razvrščanje v razrede tveganja (RiskClass) in preprečevanje vbrizgavanja ukazov.

Cikel obdelave:
untrusted input -> schema validation -> semantic validation -> PolicyEngine -> typed SafeerAction -> Provider
"""

from enum import Enum
import re
from typing import Dict, Any, Tuple, Set, Optional
from urllib.parse import urlparse

from pydantic import ValidationError
from core.devices.models import DeviceType, Device
from core.actions.models import ActionRequest
from core.actions.types import (
    RiskClass,
    DecisionType,
    OpenUrlPayload,
    LaunchAppPayload,
    KeyPayload,
    VolumePayload,
    VolumeStepPayload,
    TuneChannelPayload,
    SeekPayload,
    SearchPayload,
    TypeTextPayload,
    SwitchInputPayload,
    TypedSafeerAction,
)


class PolicyDecision:
    def __init__(
        self,
        decision: DecisionType,
        risk_class: RiskClass,
        reason: str,
        typed_action: Optional[TypedSafeerAction] = None,
        sanitized_params: Optional[Dict[str, Any]] = None,
    ):
        self.decision = decision
        self.risk_class = risk_class
        self.reason = reason
        self.typed_action = typed_action
        self.sanitized_params = sanitized_params or {}


# Dovoljena dejanja za posamezne tipe naprav
ALLOWED_ACTIONS_BY_TYPE: Dict[DeviceType, Set[str]] = {
    DeviceType.ANDROID_TV: {
        "status",
        "pair",
        "power",
        "power_on",
        "power_off",
        "wake",
        "sleep",
        "back",
        "home",
        "key",
        "open_url",
        "open_browser",
        "open_smarttube",
        "open_xplore_tv",
        "open_streamtv",
        "launch_app",
        "tune_channel",
        "play_pause",
        "seek",
        "search",
        "switch_input",
        "type_text",
        "screenshot",
        "clear_cache_and_restart",
    },
    DeviceType.AUDIO_SOUNDBAR: {
        "status",
        "set_volume",
        "volume",
        "volume_up",
        "volume_down",
        "mute",
        "unmute",
        "toggle_mute",
    },
    DeviceType.ANDROID_PHONE: {
        "status",
        "ping",
        "open_url",
    },
    DeviceType.CAST: {
        "status",
        "cast_url",
        "stop",
    },
    DeviceType.ROUTER: {
        "status",
        "ping",
    },
    DeviceType.DNS_ADBLOCK: {
        "status",
        "ping",
    },
    DeviceType.PC: {
        "status",
        "ping",
        "open_url",
    },
    DeviceType.GENERIC: {
        "status",
        "ping",
    }
}

ALLOWED_PACKAGES: Set[str] = {
    "com.example.safeerbrowser",
    "com.streamnexus.tv",
    "org.smarttube.stable",
    "com.google.android.youtube.tv",
    "org.droidtv.playtv",
}

ALLOWED_KEYCODES: Set[int] = {
    3,    # HOME
    4,    # BACK
    19,   # DPAD_UP
    20,   # DPAD_DOWN
    21,   # DPAD_LEFT
    22,   # DPAD_RIGHT
    23,   # DPAD_CENTER / OK
    24,   # VOLUME_UP
    25,   # VOLUME_DOWN
    26,   # POWER
    66,   # ENTER
    82,   # MENU
    85,   # MEDIA_PLAY_PAUSE
    86,   # MEDIA_STOP
    87,   # MEDIA_NEXT
    88,   # MEDIA_PREVIOUS
    89,   # MEDIA_REWIND
    90,   # MEDIA_FAST_FORWARD
    164,  # VOLUME_MUTE
    223,  # SLEEP
    224,  # WAKEUP
}

ALLOWED_INPUTS: Set[str] = {
    "pc",
    "ps5",
    "hdmi1",
    "hdmi2",
    "tv",
}

INJECTION_PATTERN = re.compile(r"[;&|`$<>\\]")


class PolicyEngine:
    """
    Varnostni filter, ki preveri ali je zahtevano dejanje dovoljeno.
    Združuje schema validacijo, semantični pregled in določitev razreda tveganja.
    """

    @classmethod
    def evaluate(
        cls,
        request: ActionRequest,
        device: Device,
        trust_context: Optional[Dict[str, Any]] = None
    ) -> PolicyDecision:
        action = request.action.lower().strip()
        params = dict(request.params or {})
        trust_context = trust_context or {}

        # 1. Ali je dejanje na seznamu dovoljenih za ta tip naprave?
        allowed_actions = ALLOWED_ACTIONS_BY_TYPE.get(device.type, set())
        if action not in allowed_actions:
            return PolicyDecision(
                decision=DecisionType.DENY,
                risk_class=RiskClass.DENY,
                reason=f"Dejanje '{action}' ni dovoljeno za napravo tipa {device.type.value}."
            )

        # 2. Preveri zanesljivost naprave (Trust Context)
        is_trusted = getattr(device.identity, "trusted", True) if hasattr(device, "identity") else True
        requires_confirmation = False

        # Če naprava še ni overjena, vsa dejanja razen 'status' in 'pair' zahtevajo eksplicitno potrditev
        if not is_trusted and action not in ("status", "pair"):
            requires_confirmation = True

        parsed_payload = None
        sanitized_params = dict(params)

        # 3. Schema & Semantic Validation po posameznih dejanjih
        try:
            if device.type == DeviceType.ANDROID_TV:
                if action == "key":
                    kc = params.get("keycode")
                    try:
                        kc_int = int(kc) if kc is not None else None
                    except (ValueError, TypeError):
                        kc_int = None
                    if kc_int is None or kc_int not in ALLOWED_KEYCODES:
                        return PolicyDecision(
                            decision=DecisionType.DENY,
                            risk_class=RiskClass.DENY,
                            reason=f"Neveljavna ali nedovoljena tipka keycode: {kc}."
                        )
                    payload_obj = KeyPayload(keycode=kc_int)
                    parsed_payload = payload_obj
                    sanitized_params["keycode"] = payload_obj.keycode

                elif action == "open_url":
                    raw_url = str(params.get("url", "")).strip()
                    try:
                        payload_obj = OpenUrlPayload(url=raw_url)
                        parsed_payload = payload_obj
                        sanitized_params["url"] = payload_obj.url
                    except (ValidationError, ValueError) as e:
                        msg = str(e)
                        if "shema" in msg.lower() or "scheme" in msg.lower():
                            reason_txt = f"Nedovoljena URL shema. Dovoljeni sta le http in https."
                        elif "kontrolne" in msg.lower() or "znake" in msg.lower():
                            reason_txt = "Vnos vsebuje prepovedane varnostne znake."
                        else:
                            reason_txt = f"Neveljaven URL: {msg}"
                        return PolicyDecision(
                            decision=DecisionType.DENY,
                            risk_class=RiskClass.DENY,
                            reason=reason_txt
                        )

                elif action == "launch_app":
                    raw_pkg = str(params.get("package", "")).strip()
                    try:
                        payload_obj = LaunchAppPayload(package=raw_pkg)
                        if payload_obj.package not in ALLOWED_PACKAGES:
                            return PolicyDecision(
                                decision=DecisionType.DENY,
                                risk_class=RiskClass.DENY,
                                reason=f"Zagon paketa '{raw_pkg}' ni na seznamu dovoljenih aplikacij."
                            )
                        parsed_payload = payload_obj
                        sanitized_params["package"] = payload_obj.package
                    except (ValidationError, ValueError):
                        return PolicyDecision(
                            decision=DecisionType.DENY,
                            risk_class=RiskClass.DENY,
                            reason=f"Zagon paketa '{raw_pkg}' ni na seznamu dovoljenih aplikacij."
                        )

                elif action == "tune_channel":
                    raw_ch = params.get("channel")
                    try:
                        payload_obj = TuneChannelPayload(channel=int(raw_ch))
                        parsed_payload = payload_obj
                        sanitized_params["channel"] = payload_obj.channel
                    except (ValidationError, ValueError, TypeError):
                        return PolicyDecision(
                            decision=DecisionType.DENY,
                            risk_class=RiskClass.DENY,
                            reason=f"Kanal mora biti pozitivno celo število med 1 in 9999 (prejeto: {raw_ch})."
                        )

                elif action == "seek":
                    raw_sec = params.get("seconds")
                    try:
                        payload_obj = SeekPayload(seconds=int(raw_sec))
                        parsed_payload = payload_obj
                        sanitized_params["seconds"] = payload_obj.seconds
                    except (ValidationError, ValueError, TypeError):
                        return PolicyDecision(
                            decision=DecisionType.DENY,
                            risk_class=RiskClass.DENY,
                            reason=f"Previjanje je omejeno na maksimalno +/- 7200 sekund (prejeto: {raw_sec})."
                        )

                elif action in ("search", "type_text"):
                    text = str(params.get("text", params.get("query", "")))
                    if action == "search":
                        eng = str(params.get("engine", "google"))
                        try:
                            payload_obj = SearchPayload(query=text, engine=eng)
                            parsed_payload = payload_obj
                            sanitized_params["query"] = payload_obj.query
                            sanitized_params["engine"] = payload_obj.engine
                        except (ValidationError, ValueError):
                            return PolicyDecision(
                                decision=DecisionType.DENY,
                                risk_class=RiskClass.DENY,
                                reason="Vnos vsebuje prepovedane varnostne znake (; & | ` $ < >)."
                            )
                    else:
                        try:
                            payload_obj = TypeTextPayload(text=text)
                            parsed_payload = payload_obj
                            sanitized_params["text"] = payload_obj.text
                        except (ValidationError, ValueError):
                            return PolicyDecision(
                                decision=DecisionType.DENY,
                                risk_class=RiskClass.DENY,
                                reason="Vnos vsebuje prepovedane varnostne znake (; & | ` $ < >)."
                            )

                elif action in ("open_smarttube", "open_streamtv"):
                    query = str(params.get("query", "")).strip()
                    if query:
                        try:
                            payload_obj = SearchPayload(query=query)
                            sanitized_params["query"] = payload_obj.query
                        except (ValidationError, ValueError):
                            return PolicyDecision(
                                decision=DecisionType.DENY,
                                risk_class=RiskClass.DENY,
                                reason="Vnos vsebuje prepovedane varnostne znake."
                            )

                elif action == "switch_input":
                    target_in = str(params.get("input", "")).strip().lower()
                    try:
                        payload_obj = SwitchInputPayload(input=target_in)
                        parsed_payload = payload_obj
                        sanitized_params["input"] = payload_obj.input
                    except (ValidationError, ValueError):
                        return PolicyDecision(
                            decision=DecisionType.DENY,
                            risk_class=RiskClass.DENY,
                            reason=f"Neveljaven vhod '{target_in}'. Dovoljeni: {list(ALLOWED_INPUTS)}."
                        )

                elif action == "clear_cache_and_restart":
                    # Destruktivna operacija
                    requires_confirmation = True

            elif device.type == DeviceType.AUDIO_SOUNDBAR:
                if action in ("set_volume", "volume"):
                    raw_vol = params.get("volume", params.get("level"))
                    try:
                        payload_obj = VolumePayload(volume=int(raw_vol))
                        parsed_payload = payload_obj
                        sanitized_params["volume"] = payload_obj.volume
                    except (ValidationError, ValueError, TypeError):
                        return PolicyDecision(
                            decision=DecisionType.DENY,
                            risk_class=RiskClass.DENY,
                            reason=f"Glasnost mora biti med 0 in 100 % (prejeto: {raw_vol})."
                        )

                elif action in ("volume_up", "volume_down"):
                    raw_step = params.get("step", 5)
                    try:
                        payload_obj = VolumeStepPayload(step=int(raw_step))
                        parsed_payload = payload_obj
                        sanitized_params["step"] = payload_obj.step
                    except (ValidationError, ValueError, TypeError):
                        sanitized_params["step"] = 5

        except Exception as e:
            return PolicyDecision(
                decision=DecisionType.DENY,
                risk_class=RiskClass.DENY,
                reason=f"Validacijska napaka: {e}"
            )

        # 4. Razvrstitev v RiskClass
        if requires_confirmation:
            risk = RiskClass.CONFIRM
        elif action in ("clear_cache_and_restart",):
            risk = RiskClass.CONFIRM
        else:
            risk = RiskClass.SAFE

        # Ali je uporabnik že potrdil zahtevo (npr. potrditveni modal)?
        is_user_confirmed = bool(trust_context.get("confirmed", False) or params.get("confirmed", False))
        if risk == RiskClass.CONFIRM and not is_user_confirmed:
            decision = DecisionType.REQUIRE_CONFIRMATION
            reason = f"Dejanje '{action}' zahteva izrecno potrditev uporabnika."
        else:
            decision = DecisionType.ALLOW
            reason = "Odobreno"

        typed_action = TypedSafeerAction(
            device_id=device.id,
            action=action,
            payload=parsed_payload,
            risk_class=risk,
            is_trusted_device=is_trusted
        )

        return PolicyDecision(
            decision=decision,
            risk_class=risk,
            reason=reason,
            typed_action=typed_action,
            sanitized_params=sanitized_params
        )

    @classmethod
    def validate(cls, request: ActionRequest, device: Device) -> Tuple[bool, str, ActionRequest]:
        """
        Združljivostna metoda za obstoječe klice in teste.
        """
        pol_decision = cls.evaluate(request, device)
        if pol_decision.decision == DecisionType.DENY:
            return False, pol_decision.reason, request
        elif pol_decision.decision == DecisionType.REQUIRE_CONFIRMATION:
            return False, f"VARNOSTNA ZAHTEVA: {pol_decision.reason}", request

        sanitized_req = ActionRequest(
            device_id=request.device_id,
            action=request.action.lower().strip(),
            params=pol_decision.sanitized_params
        )
        return True, pol_decision.reason, sanitized_req
