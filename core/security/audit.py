"""
AuditLogger za Safeer Control.
Strukturiran revizijski dnevnik (in-memory ring buffer + perzistentni append-only JSONL).
Sledi vsem klicem, odločitvam PolicyEngine in izidom izvedbe.
"""

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from collections import deque
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from core.actions.types import RiskClass, DecisionType


class AuditRecord(BaseModel):
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    actor_ip: str = "127.0.0.1"
    actor_type: str = "web_ui"
    device_id: str
    action: str
    risk_class: RiskClass = RiskClass.SAFE
    decision: DecisionType = DecisionType.ALLOW
    success: bool = True
    message: str = ""
    elapsed_ms: float = 0.0
    details: Optional[Dict[str, Any]] = None


class AuditLogger:
    def __init__(self, log_dir: Optional[Path] = None, max_memory_entries: int = 200):
        if log_dir is None:
            log_dir = Path(__file__).resolve().parent.parent.parent / "logs"
        self.log_dir = log_dir
        self.log_file = self.log_dir / "audit.jsonl"
        self._buffer: deque = deque(maxlen=max_memory_entries)
        self._ensure_log_dir()

    def _ensure_log_dir(self) -> None:
        try:
            self.log_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

    def record(
        self,
        device_id: str,
        action: str,
        risk_class: RiskClass,
        decision: DecisionType,
        success: bool,
        message: str = "",
        actor_ip: str = "127.0.0.1",
        actor_type: str = "web_ui",
        elapsed_ms: float = 0.0,
        details: Optional[Dict[str, Any]] = None
    ) -> AuditRecord:
        entry = AuditRecord(
            actor_ip=actor_ip,
            actor_type=actor_type,
            device_id=device_id,
            action=action,
            risk_class=risk_class,
            decision=decision,
            success=success,
            message=message,
            elapsed_ms=elapsed_ms,
            details=details
        )
        # 1. Dodaj v pomnilniški ring buffer
        self._buffer.append(entry)

        # 2. Zapiši v append-only JSONL datoteko
        try:
            line = entry.model_dump_json() + "\n"
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(line)
        except Exception as e:
            # Ne zruši izvajanja, če pisanje na disk odpove
            pass

        return entry

    def get_recent(self, limit: int = 50) -> List[Dict[str, Any]]:
        entries = list(self._buffer)
        if limit:
            entries = entries[-limit:]
        return [e.model_dump() for e in reversed(entries)]


_audit_logger_instance: Optional[AuditLogger] = None


def get_audit_logger() -> AuditLogger:
    global _audit_logger_instance
    if _audit_logger_instance is None:
        _audit_logger_instance = AuditLogger()
    return _audit_logger_instance
