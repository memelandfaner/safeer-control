"""
Action Engine za Safeer Control.
Orkestrator za varno usmerjanje in izvajanje dejanj na napravah skozi PolicyEngine in AuditLogger.
"""

import time
from typing import Optional, Dict, Any
from core.actions.models import ActionRequest, ActionResult
from core.devices.registry import DeviceRegistry, get_registry
from core.security.policy import PolicyEngine
from core.actions.types import DecisionType, RiskClass
from core.security.audit import get_audit_logger


class ActionEngine:
    def __init__(self, registry: Optional[DeviceRegistry] = None):
        self.registry = registry or get_registry()
        self.audit_logger = get_audit_logger()

    def dispatch(
        self,
        request: ActionRequest,
        actor_ip: str = "127.0.0.1",
        actor_type: str = "web_ui",
        trust_context: Optional[Dict[str, Any]] = None,
        correlation_id: Optional[str] = None
    ) -> ActionResult:
        t0 = time.time()
        dev = self.registry.get_device(request.device_id)
        if not dev:
            res = ActionResult(
                success=False,
                device_id=request.device_id,
                action=request.action,
                message=f"Naprava z ID '{request.device_id}' ni registrirana v sistemu.",
                elapsed_ms=(time.time() - t0) * 1000
            )
            self.audit_logger.record(
                device_id=request.device_id,
                action=request.action,
                risk_class=RiskClass.DENY,
                decision=DecisionType.DENY,
                success=False,
                message=res.message,
                actor_ip=actor_ip,
                actor_type=actor_type,
                elapsed_ms=res.elapsed_ms,
                correlation_id=correlation_id
            )
            return res

        # 1. Varnostni pregled preko PolicyEngine
        pol_decision = PolicyEngine.evaluate(request, dev, trust_context=trust_context)
        
        if pol_decision.decision == DecisionType.DENY:
            elapsed = (time.time() - t0) * 1000
            res = ActionResult(
                success=False,
                device_id=request.device_id,
                action=request.action,
                message=f"VARNOSTNA BLOKADA (PolicyEngine): {pol_decision.reason}",
                elapsed_ms=elapsed
            )
            self.audit_logger.record(
                device_id=request.device_id,
                action=request.action,
                risk_class=pol_decision.risk_class,
                decision=pol_decision.decision,
                success=False,
                message=res.message,
                actor_ip=actor_ip,
                actor_type=actor_type,
                elapsed_ms=elapsed,
                correlation_id=correlation_id
            )
            return res

        if pol_decision.decision == DecisionType.REQUIRE_CONFIRMATION:
            elapsed = (time.time() - t0) * 1000
            res = ActionResult(
                success=False,
                device_id=request.device_id,
                action=request.action,
                message=f"POTREBNA POTRDITEV: {pol_decision.reason}",
                data={"requires_confirmation": True, "risk_class": pol_decision.risk_class.value},
                elapsed_ms=elapsed
            )
            self.audit_logger.record(
                device_id=request.device_id,
                action=request.action,
                risk_class=pol_decision.risk_class,
                decision=pol_decision.decision,
                success=False,
                message=res.message,
                actor_ip=actor_ip,
                actor_type=actor_type,
                elapsed_ms=elapsed,
                correlation_id=correlation_id
            )
            return res

        # 2. Pridobi ponudnika naprave
        provider = self.registry.get_provider(request.device_id)
        if not provider:
            elapsed = (time.time() - t0) * 1000
            res = ActionResult(
                success=False,
                device_id=request.device_id,
                action=request.action,
                message=f"Ponudnik za napravo '{request.device_id}' ni na voljo.",
                elapsed_ms=elapsed
            )
            self.audit_logger.record(
                device_id=request.device_id,
                action=request.action,
                risk_class=pol_decision.risk_class,
                decision=pol_decision.decision,
                success=False,
                message=res.message,
                actor_ip=actor_ip,
                actor_type=actor_type,
                elapsed_ms=elapsed,
                correlation_id=correlation_id
            )
            return res

        # 3. Izvedba dejanja z že prečiščenimi parametri
        result = provider.execute_action(
            pol_decision.typed_action.action if pol_decision.typed_action else request.action,
            pol_decision.sanitized_params
        )

        # 4. Zapis v AuditLogger
        self.audit_logger.record(
            device_id=request.device_id,
            action=request.action,
            risk_class=pol_decision.risk_class,
            decision=pol_decision.decision,
            success=result.success,
            message=result.message,
            actor_ip=actor_ip,
            actor_type=actor_type,
            elapsed_ms=result.elapsed_ms,
            correlation_id=correlation_id,
            details=result.data if isinstance(result.data, dict) else None
        )

        return result


_engine_instance: Optional[ActionEngine] = None


def get_action_engine() -> ActionEngine:
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = ActionEngine()
    return _engine_instance
