"""
Konfiguracija sistema Safeer Control.
Vse nastavitve se berejo iz okoljskih spremenljivk ali .env datoteke.
Zero Token & Zero Hardcoded IP načelo.
"""

import os
import secrets
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

try:
    from dotenv import load_dotenv
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if env_path.exists():
        load_dotenv(dotenv_path=env_path)
    else:
        load_dotenv()
except ImportError:
    pass


def _get_or_create_auth_token() -> str:
    # 1. Iz okoljske spremenljivke
    token = os.getenv("SAFEER_AUTH_TOKEN", "").strip()
    if token:
        return token

    # 2. Iz lokalne zaščitene datoteke .auth_token
    token_file = Path(__file__).resolve().parent.parent / ".auth_token"
    if token_file.exists():
        try:
            saved = token_file.read_text(encoding="utf-8").strip()
            if saved:
                return saved
        except Exception:
            pass

    # 3. Ustvari nov varen 192-bitni žeton
    new_token = secrets.token_hex(24)
    try:
        token_file.write_text(new_token, encoding="utf-8")
        token_file.chmod(0o600)
    except Exception:
        pass
    return new_token


@dataclass(frozen=True)
class Settings:
    # Android TV
    tv_host: str = os.getenv("SAFEER_TV_HOST", "127.0.0.1")
    tv_port: int = int(os.getenv("SAFEER_TV_PORT", "5555"))
    tv_name: str = os.getenv("SAFEER_TV_NAME", "Living Room TV")

    # Avdio (JBL / UPnP)
    audio_host: str = os.getenv("SAFEER_AUDIO_HOST", "127.0.0.1")
    audio_port: int = int(os.getenv("SAFEER_AUDIO_PORT", "49152"))
    audio_name: str = os.getenv("SAFEER_AUDIO_NAME", "JBL Bar 300")

    # Omrežna infrastruktura
    router_host: str = os.getenv("SAFEER_ROUTER_HOST", "127.0.0.1")
    dns_host: str = os.getenv("SAFEER_DNS_HOST", "127.0.0.1")

    # Safeer Control Strežnik
    server_host: str = os.getenv("SAFEER_SERVER_HOST", "0.0.0.0")
    server_port: int = int(os.getenv("SAFEER_SERVER_PORT", "8990"))
    env: str = os.getenv("SAFEER_ENV", "development")

    # Varnost
    auth_token: str = _get_or_create_auth_token()


_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Vrne enotno instanco nastavitev (Singleton)."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
