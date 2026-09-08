"""
Action Engine za Safeer Control.
Orkestrator za varno usmerjanje in izvajanje dejanj na napravah skozi PolicyEngine.
"""

import time
from typing import Optional
from core.actions.models import ActionRequest, ActionResult
from core.devices.registry import DeviceRegistry, get_registry
from core.security.policy import PolicyEngine


class ActionEngine:
    def __init__(self, registry: Optional[DeviceRegistry] = None):
        self.registry = registry or get_registry()

    def dispatch(self, request: ActionRequest) -> ActionResult:
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
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = ActionEngine()
    return _engine_instance
