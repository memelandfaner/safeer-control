"""
CapabilityGate #2 za Safeer Companion (V0.6).
Neodvisna Android-side varnostna meja, ki NIKOLI slepo ne zaupa temu,
da je Linux odjemalec zahtevo predhodno preveril.
"""

from typing import Dict, Any, Set, Tuple
from companion.protocol import Capability


# Bela lista dovoljenih aplikacij za force-stop in vzdrževanje predpomnilnika na Android napravi
ALLOWED_COMPANION_PACKAGES: Set[str] = {
    "com.example.safeerbrowser",
    "com.streamnexus.tv",
    "org.smarttube.stable",
    "com.google.android.youtube.tv",
    "org.droidtv.playtv",
    "org.droidtv.nettvbrowser",
}

# Zaščiteni sistemski paketi, ki jih NIKOLI ni dovoljeno zaustaviti
PROTECTED_SYSTEM_PACKAGES: Set[str] = {
    "com.android.systemui",
    "android",
    "com.google.android.gms",
    "com.google.android.gsf",
    "com.android.settings",
    "com.android.vending",
}

# Bela lista varnih sistemskih nastavitev za branje (izrecno prepovedani gesla, žetoni in zasebni podatki!)
ALLOWED_SETTING_KEYS: Set[str] = {
    "stay_on_while_plugged_in",
    "animator_duration_scale",
    "transition_animation_scale",
    "window_animation_scale",
    "adb_enabled",
    "device_name",
    "airplane_mode_on",
    "bluetooth_on",
    "wifi_on",
    "screen_off_timeout",
    "development_settings_enabled",
}


class CompanionGate:
    """
    CapabilityGate #2 (Android Meja).
    Preveri in zavrne kakršnokoli nepravilnost pred klicem Shizuku mehanizma.
    """

    @classmethod
    def require(cls, capability: Capability, params: Dict[str, Any]) -> Tuple[bool, str]:
        # 1. Stroga prepoved escape hatchev ali poskusa podtikanja ukazov
        for forbidden in ("exec", "cmd", "shell", "command", "argv", "su", "root", "script"):
            if forbidden in params:
                return False, f"Varnostna kršitev (Gate #2): nedovoljeno polje '{forbidden}'."

        # 2. Preverjanje zmožnosti
        if capability == Capability.APP_FORCE_STOP:
            pkg = str(params.get("package", "")).strip()
            if not pkg:
                return False, "Parameter 'package' je obvezen za app.force_stop."
            if pkg in PROTECTED_SYSTEM_PACKAGES or pkg.startswith("com.android.") or pkg == "android":
                return False, f"Gate #2 zavrnil zaustavitev zaščitenega sistemskega paketa '{pkg}'."
            if pkg not in ALLOWED_COMPANION_PACKAGES:
                return False, f"Gate #2 zavrnil nepooblaščen paket '{pkg}'."
            return True, "Odobreno (Gate #2)"

        elif capability == Capability.SETTINGS_READ:
            ns = str(params.get("namespace", "global")).strip().lower()
            key = str(params.get("key", "")).strip()
            if ns not in ("system", "secure", "global"):
                return False, f"Gate #2: nedovoljen namespace '{ns}'."
            if not key:
                return False, "Parameter 'key' je obvezen za settings.read."
            if key not in ALLOWED_SETTING_KEYS:
                return False, f"Gate #2: ključ nastavitve '{key}' ni na seznamu varnih dovoljenih nastavitev."
            return True, "Odobreno (Gate #2)"

        elif capability == Capability.APP_CACHE_MAINTENANCE:
            pkg = str(params.get("package", "")).strip()
            if not pkg:
                return False, "Parameter 'package' je obvezen za app.cache_maintenance."
            if pkg not in ALLOWED_COMPANION_PACKAGES:
                return False, f"Gate #2: paket '{pkg}' ni na seznamu dovoljenih paketov za vzdrževanje."
            return True, "Odobreno (Gate #2)"

        return False, f"Gate #2: neznana ali nepodprta zmožnost: '{capability}'."
