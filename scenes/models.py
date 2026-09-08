"""
Podatkovni modeli za scene (Scenes) v Safeer Control V0.3 (Reliable Orchestration).
Podpira transakcijsko orkestracijo, preflight pogoje, verifikacijo pričakovanih stanj
in inteligentni rollback.
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from core.actions.models import ActionResult


class SceneExecutionStatus(str, Enum):
    COMPLETED = "COMPLETED"          # Vsi koraki so se uspešno izvedli in verificirali
    PARTIAL = "PARTIAL"              # Delni uspeh, rollback ni v celoti uspel
    ROLLED_BACK = "ROLLED_BACK"      # Napaka pri koraku, začetno stanje uspešno povrnjeno
    FAILED = "FAILED"                # Preflight padel ali popolna odpoved brez izvedbe


class PreflightRequirement(BaseModel):
    """Zahteva, ki mora biti izpolnjena PREDEN se izvede karkoli v sceni."""
    device_id: str
    require_online: bool = True
    require_trusted: bool = True


class SceneStep(BaseModel):
    """Posamezen korak z verifikacijo pričakovanega stanja in ponovitvami."""
    device_id: str
    action: str
    params: Dict[str, Any] = Field(default_factory=dict)
    expect: Dict[str, Any] = Field(default_factory=dict, description="Pričakovano stanje po izvedbi (npr. power_on, muted, volume)")
    timeout_sec: float = 4.0
    retry_count: int = 2
    retry_delay_sec: float = 0.5
    rollback_action: Optional[str] = None
    delay_after_ms: int = 0


class Scene(BaseModel):
    id: str
    name: str
    description: str = ""
    preflight: List[PreflightRequirement] = Field(default_factory=list)
    steps: List[SceneStep] = Field(default_factory=list)


class SceneExecutionReport(BaseModel):
    """Podrobno transakcijsko poročilo izvedbe scene."""
    scene_id: str
    correlation_id: str
    status: SceneExecutionStatus
    step_results: List[ActionResult] = Field(default_factory=list)
    initial_snapshots: Dict[str, Any] = Field(default_factory=dict)
    error_message: Optional[str] = None
    elapsed_ms: float = 0.0
