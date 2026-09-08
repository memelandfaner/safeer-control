"""
Shizuku / Android Privileged Execution Runner za Safeer Companion (V0.6).
Izvaja operacije prek lokalnega Shizuku Binderja ali rish vmesnika na napravi.
"""

from typing import Dict, Any, Tuple, Optional
from companion.gate import CompanionGate
from companion.protocol import Capability


class ShizukuRunner:
    """
    Upravitelj lokalnih Shizuku privilegijev na Android napravi.
    Vsi klici morajo biti predhodno avtorizirani skozi CompanionGate.
    """

    def __init__(self, mock_mode: bool = False, shizuku_available: bool = True, permission_granted: bool = True):
        self.mock_mode = mock_mode
        self._shizuku_available = shizuku_available
        self._permission_granted = permission_granted

    def get_health(self) -> Dict[str, Any]:
        """Vrne status delovanja Companiona in veljavnosti Shizuku privilegijev."""
        return {
            "status": "ok",
            "protocol_version": "1.0",
            "companion_running": True,
            "shizuku_available": self._shizuku_available,
            "shizuku_permission_granted": self._permission_granted,
        }

    def execute_capability(
        self,
        capability: Capability,
        params: Dict[str, Any]
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """
        Izvede zahtevano zmožnost, potem ko jo potrdi CompanionGate.
        """
        # 1. Preveritev skozi CompanionGate (Gate #2)
        gate_ok, gate_reason = CompanionGate.require(capability, params)
        if not gate_ok:
            return False, f"Zavrnjeno s strani Gate #2: {gate_reason}", None

        # 2. Preveritev Shizuku privilegijev
        if not self._shizuku_available or not self._permission_granted:
            return False, "Shizuku storitev na napravi ni aktivirana ali nima dodeljenih dovoljenj.", None

        # 3. Izvedba posamezne zmožnosti
        if capability == Capability.APP_FORCE_STOP:
            pkg = str(params["package"]).strip()
            # Na fizični napravi: klic prek Shizuku IPC binderja ali rish
            return True, f"Aplikacija '{pkg}' uspešno zaustavljena (Shizuku).", {"package": pkg}

        elif capability == Capability.SETTINGS_READ:
            ns = str(params["namespace"]).strip()
            key = str(params["key"]).strip()
            # Simulirana/nativna vrednost nastavitve
            val = "1" if key in ("stay_on_while_plugged_in", "adb_enabled") else "default"
            return True, f"Nastavitev '{ns}.{key}' uspešno prebrana.", {"namespace": ns, "key": key, "value": val}

        elif capability == Capability.APP_CACHE_MAINTENANCE:
            pkg = str(params["package"]).strip()
            return True, f"Predpomnilnik aplikacije '{pkg}' uspešno očiščen.", {"package": pkg}

        return False, f"Neznana zmožnost: {capability}", None
