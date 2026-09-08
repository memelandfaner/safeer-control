"""
Varnostni Policy Engine za Safeer Control.
Preverja dovoljenja in preprečuje neposredno izvajanje poljubnih shell ukazov.
"""

import re
from typing import Dict, Any, Tuple, Set
from urllib.parse import urlparse
from core.devices.models import DeviceType, Device
from core.actions.models import ActionRequest


# Dovoljena dejanja za posamezne tipe naprav
ALLOWED_ACTIONS_BY_TYPE: Dict[DeviceType, Set[str]] = {
    DeviceType.ANDROID_TV: {
        "status",
        "power",
        "power_on",
        "power_off",
        "wake",
        "sleep",
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
        "mute",
        "unmute",
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

INJECTION_PATTERN = re.compile(r"[;&|`$<>]")


class PolicyEngine:
    """
    Varnostni filter, ki preveri ali je zahtevano dejanje dovoljeno.
    """

    @classmethod
    def validate(cls, request: ActionRequest, device: Device) -> Tuple[bool, str, ActionRequest]:
        action = request.action.lower().strip()
        params = dict(request.params)

        allowed_actions = ALLOWED_ACTIONS_BY_TYPE.get(device.type, set())
        if action not in allowed_actions:
            return False, f"Dejanje '{action}' ni dovoljeno za napravo tipa {device.type.value}.", request

        if device.type == DeviceType.ANDROID_TV:
            if action == "key":
                keycode = params.get("keycode")
                if keycode is None or not isinstance(keycode, int) or keycode not in ALLOWED_KEYCODES:
                    return False, f"Neveljavna ali nedovoljena tipka keycode: {keycode}.", request

            elif action == "open_url":
                url = str(params.get("url", "")).strip()
                if not url:
                    return False, "Parameter 'url' ne sme biti prazen.", request
                parsed = urlparse(url)
                if not parsed.scheme:
                    parsed = urlparse(f"https://{url}")
                if parsed.scheme.lower() not in ("http", "https"):
                    return False, f"Nedovoljena URL shema '{parsed.scheme}'. Dovoljeni sta le http in https.", request
                params["url"] = parsed.geturl()

            elif action == "launch_app":
                pkg = str(params.get("package", "")).strip()
                if pkg not in ALLOWED_PACKAGES:
                    return False, f"Zagon paketa '{pkg}' ni na seznamu dovoljenih aplikacij.", request
                params["package"] = pkg

            elif action == "tune_channel":
                channel = params.get("channel")
                try:
                    ch_int = int(channel)
                    if ch_int <= 0 or ch_int > 9999:
                        return False, f"Kanal mora biti pozitivno celo število med 1 in 9999 (prejeto: {channel}).", request
                    params["channel"] = ch_int
                except (ValueError, TypeError):
                    return False, f"Neveljavna številka kanala: {channel}.", request

            elif action == "seek":
                seconds = params.get("seconds")
                try:
                    sec_int = int(seconds)
                    if abs(sec_int) > 7200:
                        return False, f"Previjanje je omejeno na maksimalno +/- 7200 sekund (prejeto: {seconds}).", request
                    params["seconds"] = sec_int
                except (ValueError, TypeError):
                    return False, f"Neveljavna vrednost za previjanje: {seconds}.", request

            elif action in ("search", "type_text"):
                text = str(params.get("text", params.get("query", "")))
                if INJECTION_PATTERN.search(text):
                    return False, "Vnos vsebuje prepovedane varnostne znake (; & | ` $ < >).", request
                if len(text) > 200:
                    text = text[:200]
                if action == "search":
                    params["query"] = text
                else:
                    params["text"] = text

            elif action == "switch_input":
                target_input = str(params.get("input", "")).lower().strip()
                if target_input not in ALLOWED_INPUTS:
                    return False, f"Neveljaven vhod '{target_input}'. Dovoljeni: {list(ALLOWED_INPUTS)}.", request
                params["input"] = target_input

        elif device.type == DeviceType.AUDIO_SOUNDBAR:
            if action in ("set_volume", "volume"):
                vol = params.get("volume", params.get("level"))
                try:
                    vol_int = int(vol)
                    if vol_int < 0 or vol_int > 100:
                        return False, f"Glasnost mora biti med 0 in 100 % (prejeto: {vol}).", request
                    params["volume"] = vol_int
                except (ValueError, TypeError):
                    return False, f"Neveljavna vrednost za glasnost: {vol}.", request

        sanitized = ActionRequest(
            device_id=request.device_id,
            action=action,
            params=params
        )
        return True, "Odobreno", sanitized
