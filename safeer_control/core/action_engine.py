"""
Action Engine za Safeer Control.
Osrednji orkestrator za varno usmerjanje in izvajanje dejanj na napravah.
Vsako dejanje pred klicem providerja obvezno preveri PolicyEngine!
"""

import time
from typing import Optional
from safeer_control.core.models import ActionRequest, ActionResult
from safeer_control.core.registry import DeviceRegistry, get_registry
from safeer_control.core.policy import PolicyEngine


class ActionEngine:
    def __init__(self, registry: Optional[DeviceRegistry] = None):
        self.registry = registry or get_registry()

    def dispatch(self, request: ActionRequest) -> ActionResult:
        """
        Glavna vstopna točka za izvedbo dejanja.
        Tok:
        1. Preveri obstoj naprave
        2. PolicyEngine preveri varnost in sanira parametre
        3. Provider izvede dejanje
        """
        t0 = time.time()
        dev = self.registry.get_device(request.device_id)
        if not dev:
            return ActionResult(
                success=False,
                device_id=request.device_id,
                action=request.action,
                message=f"Naprava z ID '{request.device_id}' ni registrirana v sistemu.",
                elapsed_ms=(time.time() - t0) * 1000
            )

        # 1. Varnostni pregled preko PolicyEngine
        is_allowed, reason, sanitized_req = PolicyEngine.validate(request, dev)
        if not is_allowed:
            return ActionResult(
                success=False,
                device_id=request.device_id,
                action=request.action,
                message=f"VARNOSTNA BLOKADA (PolicyEngine): {reason}",
                elapsed_ms=(time.time() - t0) * 1000
            )

        # 2. Pridobi ponudnika naprave
        provider = self.registry.get_provider(request.device_id)
        if not provider:
            return ActionResult(
                success=False,
                device_id=request.device_id,
                action=request.action,
                message=f"Ponudnik za napravo '{request.device_id}' ni na voljo.",
                elapsed_ms=(time.time() - t0) * 1000
            )

        # 3. Izvedba dejanja
        result = provider.execute_action(sanitized_req.action, sanitized_req.params)
        return result


_engine_instance: Optional[ActionEngine] = None


def get_action_engine() -> ActionEngine:
    """Vrne enotno instanco orkestratorja dejanj (Singleton)."""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = ActionEngine()
    return _engine_instance
