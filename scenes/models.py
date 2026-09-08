"""
Podatkovni modeli za scene (Scenes) v Safeer Control.
"""

from typing import Any, Dict, List
from pydantic import BaseModel, Field


class SceneStep(BaseModel):
    device_id: str
    action: str
    params: Dict[str, Any] = Field(default_factory=dict)
    delay_after_ms: int = 0


class Scene(BaseModel):
    id: str
    name: str
    description: str = ""
    steps: List[SceneStep] = Field(default_factory=list)
