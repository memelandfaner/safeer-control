"""
Scene Engine za Safeer Control.
Avtomatizacija scen (kino način, glasba, nočni izklop).
"""

import time
from typing import Dict, List, Optional
from core.actions.models import ActionRequest, ActionResult
from core.actions.engine import ActionEngine, get_action_engine
from scenes.models import Scene, SceneStep


class SceneEngine:
    def __init__(self, action_engine: Optional[ActionEngine] = None):
        self.action_engine = action_engine or get_action_engine()
        self._scenes: Dict[str, Scene] = {}
        self._register_default_scenes()

    def _register_default_scenes(self) -> None:
        self.register_scene(Scene(
            id="cinema",
            name="🎬 Kinematografski način",
            description="Prebudi televizor, odklene zvok JBL, nastavi glasnost na 45 % in zažene Safeer Browser.",
            steps=[
                SceneStep(device_id="living_room_tv", action="wake", delay_after_ms=300),
                SceneStep(device_id="living_room_audio", action="unmute", delay_after_ms=200),
                SceneStep(device_id="living_room_audio", action="set_volume", params={"volume": 45}, delay_after_ms=200),
                SceneStep(device_id="living_room_tv", action="open_browser", delay_after_ms=0),
            ]
        ))

        self.register_scene(Scene(
            id="music",
            name="🎵 Glasbeni način",
            description="Prebudi TV, odklene JBL, nastavi glasnost na 30 % in odpre SmartTube.",
            steps=[
                SceneStep(device_id="living_room_tv", action="wake", delay_after_ms=300),
                SceneStep(device_id="living_room_audio", action="unmute", delay_after_ms=200),
                SceneStep(device_id="living_room_audio", action="set_volume", params={"volume": 30}, delay_after_ms=200),
                SceneStep(device_id="living_room_tv", action="open_smarttube", delay_after_ms=0),
            ]
        ))

        self.register_scene(Scene(
            id="power_off",
            name="🌙 Nočni izklop",
            description="Preklopi televizor v stanje spanja (Sleep).",
            steps=[
                SceneStep(device_id="living_room_tv", action="sleep", delay_after_ms=0),
            ]
        ))

    def register_scene(self, scene: Scene) -> None:
        self._scenes[scene.id] = scene

    def list_scenes(self) -> List[Scene]:
        return list(self._scenes.values())

    def get_scene(self, scene_id: str) -> Optional[Scene]:
        return self._scenes.get(scene_id)

    def execute_scene(self, scene_id: str) -> List[ActionResult]:
        scene = self.get_scene(scene_id)
        if not scene:
            return [ActionResult(
                success=False,
                device_id="",
                action=f"scene:{scene_id}",
                message=f"Scena z ID '{scene_id}' ne obstaja."
            )]

        results = []
        for step in scene.steps:
            req = ActionRequest(
                device_id=step.device_id,
                action=step.action,
                params=step.params
            )
            res = self.action_engine.dispatch(req)
            results.append(res)

            if step.delay_after_ms > 0:
                time.sleep(step.delay_after_ms / 1000.0)

        return results


_scene_engine_instance: Optional[SceneEngine] = None


def get_scene_engine() -> SceneEngine:
    global _scene_engine_instance
    if _scene_engine_instance is None:
        _scene_engine_instance = SceneEngine()
    return _scene_engine_instance
