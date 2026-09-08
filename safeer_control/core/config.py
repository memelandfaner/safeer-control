"""
Konfiguracija sistema Safeer Control.
Vse nastavitve se berejo iz okoljskih spremenljivk ali .env datoteke.
Zero Token & Zero Hardcoded IP načelo: noben zasebni IP se ne shranjuje v kodo.
"""

import os
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

try:
    from dotenv import load_dotenv
    # Poišči .env v mapi projekta ali nadrejenih mapah
    env_path = Path(__file__).resolve().parent.parent.parent / ".env"
    if env_path.exists():
        load_dotenv(dotenv_path=env_path)
    else:
        load_dotenv()
except ImportError:
    pass


@dataclass(frozen=True)
class Settings:
    # Android TV
    tv_host: str = os.getenv("SAFEER_TV_HOST", "127.0.0.1")
    tv_port: int = int(os.getenv("SAFEER_TV_PORT", "5555"))
    tv_name: str = os.getenv("SAFEER_TV_NAME", "Android TV")

    # Avdio (JBL / UPnP)
    audio_host: str = os.getenv("SAFEER_AUDIO_HOST", "127.0.0.1")
    audio_port: int = int(os.getenv("SAFEER_AUDIO_PORT", "49152"))
    audio_name: str = os.getenv("SAFEER_AUDIO_NAME", "JBL Bar 300")

    # Omrežna infrastruktura
    router_host: str = os.getenv("SAFEER_ROUTER_HOST", "127.0.0.1")
    dns_host: str = os.getenv("SAFEER_DNS_HOST", "127.0.0.1")

    # Safeer Control Strežnik
    server_host: str = os.getenv("SAFEER_SERVER_HOST", "0.0.0.0")
    server_port: int = int(os.getenv("SAFEER_SERVER_PORT", "8989"))
    env: str = os.getenv("SAFEER_ENV", "development")

    # Varnost
    auth_token: Optional[str] = os.getenv("SAFEER_AUTH_TOKEN", None)


_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Vrne enotno instanco nastavitev (Singleton)."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
