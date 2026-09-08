"""
Privileged Capability Gate za ShizukuProvider in Safeer Companion (V0.5).
Uveljavlja temeljni varnostni invariant:
No code path from AI/user-controlled input may reach Shizuku except
through PolicyEngine -> CapabilityGate -> a predefined typed capability operation.
"""

from enum import Enum
from typing import Dict, Any, Set, Tuple, Optional


class Capability(str, Enum):
    APP_FORCE_STOP = "app.force_stop"
    SETTINGS_READ = "settings.read"
    APP_CACHE_MAINTENANCE = "app.cache_maintenance"


class CapabilityAccessDeniedError(PermissionError):
    """Sproženo ob poskusu neavtoriziranega dostopa ali neveljavnih parametrov zmožnosti."""
    pass


# Bela lista dovoljenih aplikacij za force-stop in vzdrževanje predpomnilnika
ALLOWED_MAINTENANCE_PACKAGES: Set[str] = {
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

# Bela lista varnih sistemskih nastavitev za branje (nobenih občutljivih podatkov ali žetonov!)
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


class CapabilityGate:
    """
    Stroga varnostna vrata za privilegirane operacije.
    Preveri skladnost zahteve, predhodno odobri operacijo in prepreči kakršenkoli nepooblaščen dostop.
    """

    @classmethod
    def require(cls, capability: Capability, params: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Preveri veljavnost zahteve glede na zahtevano zmožnost in parametre.
        Vrne (True, reason) ali (False, error_reason).
        """
        # 1. Stroga prepoved poljubnih ukazov ali escape hatch-ev
        for forbidden in ("exec", "cmd", "shell", "command", "argv", "su", "root", "script"):
            if forbidden in params:
                return False, f"Varnostna kršitev: poljubno izvajanje ukazov ('{forbidden}') je strogo prepovedano."

        # 2. Preveri zmožnost
        if capability == Capability.APP_FORCE_STOP:
            pkg = str(params.get("package", "")).strip()
            if not pkg:
                return False, "Parameter 'package' je obvezen za app.force_stop."
            if pkg in PROTECTED_SYSTEM_PACKAGES or pkg.startswith("com.android.") or pkg == "android":
                return False, f"Zaustavitev zaščitenega sistemskega paketa '{pkg}' je prepovedana."
            if pkg not in ALLOWED_MAINTENANCE_PACKAGES:
                return False, f"Paket '{pkg}' ni na seznamu odobrenih aplikacij za upravljanje."
            return True, "Odobreno"

        elif capability == Capability.SETTINGS_READ:
            ns = str(params.get("namespace", "global")).strip().lower()
            key = str(params.get("key", "")).strip()
            if ns not in ("system", "secure", "global"):
                return False, f"Nedovoljen settings namespace '{ns}'. Dovoljeni so: system, secure, global."
            if not key:
                return False, "Parameter 'key' je obvezen za settings.read."
            if key not in ALLOWED_SETTING_KEYS:
                return False, f"Ključ nastavitve '{key}' ni na seznamu varnih dovoljenih nastavitev."
            return True, "Odobreno"

        elif capability == Capability.APP_CACHE_MAINTENANCE:
            pkg = str(params.get("package", "")).strip()
            if not pkg:
                return False, "Parameter 'package' je obvezen za app.cache_maintenance."
            if pkg not in ALLOWED_MAINTENANCE_PACKAGES:
                return False, f"Paket '{pkg}' ni na seznamu odobrenih aplikacij za vzdrževanje predpomnilnika."
            return True, "Odobreno"

        return False, f"Neznana ali nepodprta zmožnost: '{capability}'."
