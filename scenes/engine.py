"""
Scene Engine 2.0 za Safeer Control (V0.3 — Reliable Orchestration).
Transakcijska orkestracija s Preflight preverjanjem, zajemom stanj (Snapshots),
verifikacijo pričakovanih stanj (Expectations), inteligentnim stanjem-zavednim rollbackom
in enotnim Correlation ID v revizijskem dnevniku.
"""

import time
import uuid
from typing import Dict, List, Optional, Any, Tuple
from core.actions.models import ActionRequest, ActionResult
from core.actions.engine import ActionEngine, get_action_engine
from core.devices.registry import DeviceRegistry, get_registry
from core.security.audit import get_audit_logger
from core.actions.types import RiskClass, DecisionType
from scenes.models import (
    Scene,
    SceneStep,
    PreflightRequirement,
    SceneExecutionStatus,
    SceneExecutionReport
)


class SceneEngine:
    def __init__(
        self,
        action_engine: Optional[ActionEngine] = None,
        registry: Optional[DeviceRegistry] = None
    ):
        self.action_engine = action_engine or get_action_engine()
        self.registry = registry or get_registry()
        self.audit_logger = get_audit_logger()
        self._scenes: Dict[str, Scene] = {}
        self._register_default_scenes()

    def _register_default_scenes(self) -> None:
        # 🎬 1. CINEMA NAČIN (V0.3 Prava Transakcijska Integracija)
        self.register_scene(Scene(
            id="cinema",
            name="🎬 Kinematografski način",
            description="Prebudi televizor, odklene zvok JBL, nastavi glasnost na 45 % in zažene Safeer Browser z verifikacijo stanj.",
            preflight=[
                PreflightRequirement(device_id="living_room_tv", require_online=True, require_trusted=True),
                PreflightRequirement(device_id="living_room_audio", require_online=True, require_trusted=False),
            ],
            steps=[
                # 1. TV wake -> preveri power_on
                SceneStep(
                    device_id="living_room_tv",
                    action="wake",
                    expect={"power_on": True},
                    timeout_sec=4.0,
                    retry_count=2,
                    retry_delay_sec=0.5,
                    delay_after_ms=200
                ),
                # 2. JBL unmute -> hardware-aware no-op če je že unmuted -> preveri muted == False
                SceneStep(
                    device_id="living_room_audio",
                    action="unmute",
                    expect={"muted": False},
                    timeout_sec=3.0,
                    retry_count=2,
                    retry_delay_sec=0.3,
                    delay_after_ms=200
                ),
                # 3. JBL volume 45 -> preveri volume ≈ 45
                SceneStep(
                    device_id="living_room_audio",
                    action="set_volume",
                    params={"volume": 45},
                    expect={"volume": 45},
                    timeout_sec=3.0,
                    retry_count=2,
                    retry_delay_sec=0.3,
                    delay_after_ms=200
                ),
                # 4. launch Safeer Browser -> preveri foreground_app
                SceneStep(
                    device_id="living_room_tv",
                    action="open_browser",
                    expect={"active_app": "Safeer Browser"},
                    timeout_sec=4.0,
                    retry_count=2,
                    retry_delay_sec=0.5,
                    delay_after_ms=0
                ),
            ]
        ))

        # 🎵 2. GLASBENI NAČIN
        self.register_scene(Scene(
            id="music",
            name="🎵 Glasbeni način",
            description="Prebudi TV, odklene JBL, nastavi glasnost na 30 % in odpre SmartTube.",
            preflight=[
                PreflightRequirement(device_id="living_room_tv", require_online=True, require_trusted=True),
                PreflightRequirement(device_id="living_room_audio", require_online=True, require_trusted=False),
            ],
            steps=[
                SceneStep(device_id="living_room_tv", action="wake", expect={"power_on": True}, delay_after_ms=200),
                SceneStep(device_id="living_room_audio", action="unmute", expect={"muted": False}, delay_after_ms=200),
                SceneStep(device_id="living_room_audio", action="set_volume", params={"volume": 30}, expect={"volume": 30}, delay_after_ms=200),
                SceneStep(device_id="living_room_tv", action="open_smarttube", delay_after_ms=0),
            ]
        ))

        # 🌙 3. NOČNI IZKLOP
        self.register_scene(Scene(
            id="power_off",
            name="🌙 Nočni izklop",
            description="Preklopi televizor v stanje spanja (Sleep).",
            preflight=[
                PreflightRequirement(device_id="living_room_tv", require_online=True, require_trusted=False),
            ],
            steps=[
                SceneStep(device_id="living_room_tv", action="sleep", expect={"power_on": False}, delay_after_ms=0),
            ]
        ))

    def register_scene(self, scene: Scene) -> None:
        self._scenes[scene.id] = scene

    def list_scenes(self) -> List[Scene]:
        return list(self._scenes.values())

    def get_scene(self, scene_id: str) -> Optional[Scene]:
        return self._scenes.get(scene_id)

    def _verify_step_expectation(self, device_id: str, expect: Dict[str, Any]) -> Tuple[bool, str]:
        """Preveri, ali trenutno stanje naprave ustreza pričakovanjem."""
        if not expect:
            return True, "Brez pogojev pričakovanja"

        prov = self.registry.get_provider(device_id)
        if not prov:
            return False, f"Ponudnik za '{device_id}' ni dosegljiv za preverjanje stanja."

        stat = prov.get_status()
        if not stat.online:
            return False, f"Naprava '{device_id}' je med izvajanjem izgubila povezavo."

        for key, exp_val in expect.items():
            if key == "power_on":
                if stat.power_on != exp_val:
                    return False, f"Pričakovano stanje zaslona power_on={exp_val}, dejansko {stat.power_on}."
            elif key == "muted":
                if stat.muted != exp_val:
                    return False, f"Pričakovano stanje utišanja muted={exp_val}, dejansko {stat.muted}."
            elif key == "volume":
                if stat.volume is None or abs(stat.volume - int(exp_val)) > 3:
                    return False, f"Pričakovana glasnost ~{exp_val} %, dejansko {stat.volume} %."
            elif key == "active_app":
                if not stat.active_app or str(exp_val).lower() not in stat.active_app.lower():
                    return False, f"Pričakovan aktivni program '{exp_val}', dejansko '{stat.active_app}'."

        return True, "Stanje uspešno verificirano"

    def execute_scene(
        self,
        scene_id: str,
        actor_ip: str = "127.0.0.1",
        actor_type: str = "scene",
        optional_url: Optional[str] = None
    ) -> SceneExecutionReport:
        t0 = time.time()
        correlation_id = f"tx_scene_{scene_id}_{uuid.uuid4().hex[:8]}"

        scene = self.get_scene(scene_id)
        if not scene:
            err = f"Scena z ID '{scene_id}' ne obstaja."
            self.audit_logger.record(
                device_id="system",
                action=f"scene:{scene_id}",
                risk_class=RiskClass.DENY,
                decision=DecisionType.DENY,
                success=False,
                message=err,
                actor_ip=actor_ip,
                actor_type=actor_type,
                correlation_id=correlation_id
            )
            return SceneExecutionReport(
                scene_id=scene_id,
                correlation_id=correlation_id,
                status=SceneExecutionStatus.FAILED,
                error_message=err,
                elapsed_ms=(time.time() - t0) * 1000
            )

        # 1. PREFLIGHT PREVERJANJE
        for req in scene.preflight:
            dev = self.registry.get_device(req.device_id)
            prov = self.registry.get_provider(req.device_id)
            if not dev or not prov:
                err = f"Preflight padel: Naprava '{req.device_id}' ni registrirana."
                return self._abort_preflight(scene_id, correlation_id, err, actor_ip, actor_type, t0)

            stat = prov.get_status()
            if req.require_online and not stat.online:
                err = f"Preflight padel: Naprava '{dev.name}' ({dev.host}) ni dosegljiva v omrežju."
                return self._abort_preflight(scene_id, correlation_id, err, actor_ip, actor_type, t0)

            is_trusted = getattr(dev.identity, "trusted", True) if hasattr(dev, "identity") else True
            if req.require_trusted and not is_trusted:
                err = f"Preflight padel: Naprava '{dev.name}' ni avtorizirana v Safeer Trust Modelu."
                return self._abort_preflight(scene_id, correlation_id, err, actor_ip, actor_type, t0)

        # 2. ZAJEM ZAČETNEGA STANJA (INITIAL STATE SNAPSHOTS)
        snapshots: Dict[str, Any] = {}
        for step in scene.steps:
            if step.device_id not in snapshots:
                prov = self.registry.get_provider(step.device_id)
                if prov:
                    stat = prov.get_status()
                    snapshots[step.device_id] = stat.model_dump()

        executed_steps: List[Tuple[SceneStep, ActionResult]] = []
        step_results: List[ActionResult] = []
        failed_step_error = None

        # 3. TRANSAKCIJSKA IZVEDBA PO KORAKIH Z VERIFIKACIJO
        steps_to_run = list(scene.steps)
        if optional_url and scene_id == "cinema":
            steps_to_run.append(
                SceneStep(
                    device_id="living_room_tv",
                    action="open_url",
                    params={"url": optional_url},
                    timeout_sec=3.0,
                    retry_count=1
                )
            )

        for step_idx, step in enumerate(steps_to_run):
            step_success = False
            last_res = None

            # Retry zanka za posamezen korak
            for attempt in range(step.retry_count + 1):
                act_req = ActionRequest(
                    device_id=step.device_id,
                    action=step.action,
                    params=step.params
                )
                last_res = self.action_engine.dispatch(
                    act_req,
                    actor_ip=actor_ip,
                    actor_type=actor_type,
                    correlation_id=correlation_id
                )

                if last_res.success:
                    # Počakaj kratek trenutek, če naprava potrebuje čas za preklop stanja
                    if step.delay_after_ms > 0:
                        time.sleep(step.delay_after_ms / 1000.0)

                    # Verificiraj pričakovano stanje
                    verified, v_msg = self._verify_step_expectation(step.device_id, step.expect)
                    if verified:
                        step_success = True
                        break
                    else:
                        last_res.success = False
                        last_res.message = f"{last_res.message} (Preverjanje stanja odpovedalo: {v_msg})"

                if attempt < step.retry_count:
                    time.sleep(step.retry_delay_sec)

            step_results.append(last_res)
            if step_success:
                executed_steps.append((step, last_res))
            else:
                failed_step_error = f"Korak {step_idx + 1} ({step.device_id} -> {step.action}) ni uspel: {last_res.message}"
                break

        # 4. ČE JE KATERIKOLI KORAK ODPOVEDAL: INTELIGENTNI ROLLBACK
        if failed_step_error:
            rollback_ok = self._perform_intelligent_rollback(
                executed_steps=executed_steps,
                snapshots=snapshots,
                actor_ip=actor_ip,
                actor_type=actor_type,
                correlation_id=correlation_id
            )
            final_status = SceneExecutionStatus.ROLLED_BACK if rollback_ok else SceneExecutionStatus.PARTIAL
            elapsed = (time.time() - t0) * 1000

            self.audit_logger.record(
                device_id="system",
                action=f"scene:{scene_id}",
                risk_class=RiskClass.CONFIRM,
                decision=DecisionType.ALLOW,
                success=False,
                message=f"Scena prekinjena. Rollback izveden: {rollback_ok}. Napaka: {failed_step_error}",
                actor_ip=actor_ip,
                actor_type=actor_type,
                elapsed_ms=elapsed,
                correlation_id=correlation_id,
                details={"status": final_status.value, "error": failed_step_error}
            )

            return SceneExecutionReport(
                scene_id=scene_id,
                correlation_id=correlation_id,
                status=final_status,
                step_results=step_results,
                initial_snapshots=snapshots,
                error_message=failed_step_error,
                elapsed_ms=elapsed
            )

        # 5. USPEŠEN ZAKLJUČEK (COMPLETED)
        elapsed = (time.time() - t0) * 1000
        self.audit_logger.record(
            device_id="system",
            action=f"scene:{scene_id}",
            risk_class=RiskClass.SAFE,
            decision=DecisionType.ALLOW,
            success=True,
            message=f"Scena '{scene.name}' uspešno izvedena in verificirana v celoti.",
            actor_ip=actor_ip,
            actor_type=actor_type,
            elapsed_ms=elapsed,
            correlation_id=correlation_id,
            details={"status": SceneExecutionStatus.COMPLETED.value, "steps_count": len(step_results)}
        )

        return SceneExecutionReport(
            scene_id=scene_id,
            correlation_id=correlation_id,
            status=SceneExecutionStatus.COMPLETED,
            step_results=step_results,
            initial_snapshots=snapshots,
            elapsed_ms=elapsed
        )

    def _abort_preflight(
        self,
        scene_id: str,
        correlation_id: str,
        err: str,
        actor_ip: str,
        actor_type: str,
        t0: float
    ) -> SceneExecutionReport:
        elapsed = (time.time() - t0) * 1000
        self.audit_logger.record(
            device_id="system",
            action=f"scene:{scene_id}:preflight",
            risk_class=RiskClass.SAFE,
            decision=DecisionType.DENY,
            success=False,
            message=err,
            actor_ip=actor_ip,
            actor_type=actor_type,
            elapsed_ms=elapsed,
            correlation_id=correlation_id
        )
        return SceneExecutionReport(
            scene_id=scene_id,
            correlation_id=correlation_id,
            status=SceneExecutionStatus.FAILED,
            error_message=err,
            elapsed_ms=elapsed
        )

    def _perform_intelligent_rollback(
        self,
        executed_steps: List[Tuple[SceneStep, ActionResult]],
        snapshots: Dict[str, Any],
        actor_ip: str,
        actor_type: str,
        correlation_id: str
    ) -> bool:
        """
        Povrne naprave v točno začetno stanje na podlagi zajetega posnetka (Snapshot).
        Ne nastavlja privzetih vrednosti, ampak resnično prejšnje stanje!
        """
        all_rollback_ok = True

        for step, _ in reversed(executed_steps):
            dev_id = step.device_id
            snap = snapshots.get(dev_id, {})

            # 1. Povrnitev glasnosti JBL na začetno vrednost
            if dev_id == "living_room_audio" and step.action in ("set_volume", "volume"):
                prev_vol = snap.get("volume")
                if prev_vol is not None and prev_vol >= 0:
                    r = self.action_engine.dispatch(
                        ActionRequest(device_id=dev_id, action="set_volume", params={"volume": prev_vol}),
                        actor_ip=actor_ip,
                        actor_type=actor_type,
                        correlation_id=correlation_id
                    )
                    if not r.success:
                        all_rollback_ok = False

            # 2. Povrnitev mute stanja JBL
            elif dev_id == "living_room_audio" and step.action == "unmute":
                was_muted = snap.get("muted", False)
                if was_muted:
                    r = self.action_engine.dispatch(
                        ActionRequest(device_id=dev_id, action="mute"),
                        actor_ip=actor_ip,
                        actor_type=actor_type,
                        correlation_id=correlation_id
                    )
                    if not r.success:
                        all_rollback_ok = False

            # 3. Povrnitev stanja zaslona TV
            elif dev_id == "living_room_tv" and step.action in ("wake", "power_on"):
                was_awake = snap.get("power_on", False)
                if not was_awake:
                    r = self.action_engine.dispatch(
                        ActionRequest(device_id=dev_id, action="sleep"),
                        actor_ip=actor_ip,
                        actor_type=actor_type,
                        correlation_id=correlation_id
                    )
                    if not r.success:
                        all_rollback_ok = False

        return all_rollback_ok


_scene_engine_instance: Optional[SceneEngine] = None


def get_scene_engine() -> SceneEngine:
    global _scene_engine_instance
    if _scene_engine_instance is None:
        _scene_engine_instance = SceneEngine()
    return _scene_engine_instance
