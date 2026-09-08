"""
Podatkovni modeli za dejanja (Actions) v Safeer Control.
"""

from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class ActionRequest(BaseModel):
    device_id: str
    action: str
    params: Dict[str, Any] = Field(default_factory=dict)


class ActionResult(BaseModel):
    success: bool
    device_id: str
    action: str
    message: str = ""
    data: Optional[Any] = None
    elapsed_ms: float = 0.0
