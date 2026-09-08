"""
Upravitelj sej in enokratnih vstopnic (Short-Lived Sessions & Single-Use Tickets) za Safeer Control V0.2.1.
Preprečuje kroženje dolgoročnega Safeer Auth Tokena po omrežju in izpostavljanje skrivnosti v URL-jih.
"""

import time
import secrets
from typing import Dict, Optional
from pydantic import BaseModel, Field


class SessionInfo(BaseModel):
    session_id: str
    created_at: float = Field(default_factory=time.time)
    expires_at: float
    client_ip: str = "127.0.0.1"


class SessionManager:
    """
    Vpomnilniški upravitelj varnih kratkotrajnih sej in enokratnih vstopnic za WebSocket.
    """

    def __init__(self, default_session_ttl: int = 86400, ticket_ttl: int = 30):
        self.default_session_ttl = default_session_ttl
        self.ticket_ttl = ticket_ttl
        self._sessions: Dict[str, SessionInfo] = {}
        self._tickets: Dict[str, float] = {}  # ticket -> expires_at

    def create_session(self, client_ip: str = "127.0.0.1", ttl: Optional[int] = None) -> str:
        """Ustvari novo kratkotrajno sejo (privzeto 24 ur)."""
        session_id = f"saf_sess_{secrets.token_hex(24)}"
        now = time.time()
        expires = now + (ttl or self.default_session_ttl)
        self._sessions[session_id] = SessionInfo(
            session_id=session_id,
            created_at=now,
            expires_at=expires,
            client_ip=client_ip
        )
        self._cleanup()
        return session_id

    def validate_session(self, session_id: str) -> bool:
        """Preveri veljavnost seje in iztekel čas."""
        if not session_id or session_id not in self._sessions:
            return False
        info = self._sessions[session_id]
        if time.time() > info.expires_at:
            del self._sessions[session_id]
            return False
        return True

    def revoke_session(self, session_id: str) -> None:
        """Prekliče sejo ob odjavi."""
        self._sessions.pop(session_id, None)

    def create_ws_ticket(self) -> str:
        """Ustvari varno enokratno vstopnico (Single-Use Ticket) z veljavnostjo 30 sekund."""
        ticket = f"saf_tkt_{secrets.token_hex(16)}"
        self._tickets[ticket] = time.time() + self.ticket_ttl
        self._cleanup()
        return ticket

    def consume_ws_ticket(self, ticket: str) -> bool:
        """Porabi enokratno vstopnico za vzpostavitev WebSocket povezave (enkratna uporaba!)."""
        if not ticket or ticket not in self._tickets:
            return False
        expires_at = self._tickets.pop(ticket)
        return time.time() <= expires_at

    def _cleanup(self) -> None:
        """Čiščenje poteklih sej in vstopnic."""
        now = time.time()
        expired_sessions = [s_id for s_id, info in self._sessions.items() if now > info.expires_at]
        for s_id in expired_sessions:
            del self._sessions[s_id]

        expired_tickets = [t for t, exp in self._tickets.items() if now > exp]
        for t in expired_tickets:
            del self._tickets[t]


_session_manager_instance: Optional[SessionManager] = None


def get_session_manager() -> SessionManager:
    global _session_manager_instance
    if _session_manager_instance is None:
        _session_manager_instance = SessionManager()
    return _session_manager_instance
