"""
Podatkovni modeli za dejanja (Actions) v Safeer Control.
"""

import uuid
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class ActionRequest(BaseModel):
    action_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    device_id: str
    action: str
    params: Dict[str, Any] = Field(default_factory=dict)


class ActionResult(BaseModel):
    action_id: Optional[str] = None
    success: bool
    device_id: str
    action: str
    message: str = ""
    data: Optional[Any] = None
    elapsed_ms: float = 0.0
