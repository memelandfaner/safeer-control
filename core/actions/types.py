"""
Tipizirani modeli za dejanja in preverjanje sheme vhodnih podatkov (SafeerAction).
Zagotavlja, da ponudnik (Provider) nikoli ne prejme surovega ali nepreverjenega vnosa.
"""

from enum import Enum
import re
from typing import Any, Dict, Optional, Set
from urllib.parse import urlparse, unquote
from pydantic import BaseModel, Field, field_validator


class RiskClass(str, Enum):
    SAFE = "SAFE"            # Nenevarna dejanja (status, dpad, play/pause, volume +-10%, Safeer na seznanjeni napravi)
    CONFIRM = "CONFIRM"      # Zahteva potrditev (power, force-stop, clear-cache, skok glasnosti >30%, neseznanjena naprava)
    DENY = "DENY"            # Samodejno zavrnjeno (nedovoljeni ukazi, nevarne sheme, neznani paketi, vrivanje znakov)


class DecisionType(str, Enum):
    ALLOW = "ALLOW"
    REQUIRE_CONFIRMATION = "REQUIRE_CONFIRMATION"
    DENY = "DENY"


class OpenUrlPayload(BaseModel):
    url: str = Field(..., max_length=2048, description="Validiran in varen spletni naslov")

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        s = v.strip()
        if not s:
            raise ValueError("URL ne sme biti prazen.")

        # 1. Razčleni URL in preveri eksplicitne dovoljene sheme (najprej shema!)
        parsed = urlparse(s)
        if not parsed.scheme:
            s = f"https://{s}"
            parsed = urlparse(s)

        scheme = parsed.scheme.lower()
        if scheme not in ("http", "https"):
            raise ValueError(f"Nedovoljena URL shema '{scheme}'. Dovoljeni sta le http in https.")

        if not parsed.netloc:
            raise ValueError("URL mora imeti veljavno domensko ime.")

        # 2. Preveri kontrolne znake, nove vrstice in shell metaznake
        if any(c in s for c in ("\r", "\n", "\x00", ";", "&", "|", "`", "$", "<", ">")):
            raise ValueError("URL vsebuje nedovoljene kontrolne ali lupinske znake.")

        # 3. Preveri dvojno URL kodiranje
        decoded_once = unquote(s)
        if "%25" in s or ("%" in decoded_once and any(c in decoded_once for c in (";", "&", "|", "`", "$"))):
            raise ValueError("Zaznano sumljivo večkratno URL kodiranje.")

        return s


class LaunchAppPayload(BaseModel):
    package: str = Field(..., max_length=128, description="Ime aplikacijskega paketa")

    @field_validator("package")
    @classmethod
    def validate_package(cls, v: str) -> str:
        pkg = v.strip()
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$", pkg):
            raise ValueError(f"Neveljaven format imena paketa: '{pkg}'")
        return pkg


class KeyPayload(BaseModel):
    keycode: int = Field(..., ge=1, le=300, description="Android tipka keycode")


class VolumePayload(BaseModel):
    volume: int = Field(..., ge=0, le=100, description="Ciljna glasnost v odstotkih")


class VolumeStepPayload(BaseModel):
    step: int = Field(default=5, ge=1, le=25, description="Korak spremembe glasnosti")


class TuneChannelPayload(BaseModel):
    channel: int = Field(..., ge=1, le=9999, description="Številka TV kanala")


class SeekPayload(BaseModel):
    seconds: int = Field(..., ge=-7200, le=7200, description="Previjanje v sekundah")


class SearchPayload(BaseModel):
    query: str = Field(..., max_length=200, description="Iskalni niz")
    engine: str = Field(default="google", max_length=32, description="Iskalnik")

    @field_validator("query")
    @classmethod
    def validate_query(cls, v: str) -> str:
        q = v.strip()
        if any(c in q for c in ("\r", "\n", "\x00", ";", "&", "|", "`", "$", "<", ">", "\\")):
            raise ValueError("Iskalni niz vsebuje nedovoljene znake.")
        return q

    @field_validator("engine")
    @classmethod
    def validate_engine(cls, v: str) -> str:
        eng = v.strip().lower()
        if eng not in ("google", "youtube", "smarttube"):
            return "google"
        return eng


class TypeTextPayload(BaseModel):
    text: str = Field(..., max_length=200, description="Varno besedilo za vnos")

    @field_validator("text")
    @classmethod
    def validate_text(cls, v: str) -> str:
        t = v.strip()
        if any(c in t for c in ("\r", "\n", "\x00", ";", "&", "|", "`", "$", "<", ">", "\\")):
            raise ValueError("Vnosno besedilo vsebuje nedovoljene znake.")
        return t


class SwitchInputPayload(BaseModel):
    input: str = Field(..., max_length=20, description="Ciljni TV vhod")

    @field_validator("input")
    @classmethod
    def validate_input(cls, v: str) -> str:
        inp = v.strip().lower()
        if inp not in ("pc", "ps5", "hdmi1", "hdmi2", "tv"):
            raise ValueError(f"Neveljaven TV vhod '{inp}'.")
        return inp


class ShizukuForceStopPayload(BaseModel):
    package: str = Field(..., max_length=128, description="Ime aplikacijskega paketa za zaustavitev")

    @field_validator("package")
    @classmethod
    def validate_package(cls, v: str) -> str:
        pkg = v.strip()
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$", pkg):
            raise ValueError(f"Neveljaven format imena paketa: '{pkg}'")
        return pkg


class ShizukuSettingsReadPayload(BaseModel):
    namespace: str = Field(default="global", max_length=16, description="Settings namespace (system, secure, global)")
    key: str = Field(..., max_length=64, description="Nastavitveni ključ")

    @field_validator("namespace")
    @classmethod
    def validate_namespace(cls, v: str) -> str:
        ns = v.strip().lower()
        if ns not in ("system", "secure", "global"):
            raise ValueError(f"Neveljaven namespace '{ns}'. Dovoljeni: system, secure, global.")
        return ns

    @field_validator("key")
    @classmethod
    def validate_key(cls, v: str) -> str:
        k = v.strip()
        if not re.match(r"^[a-zA-Z0-9_]+$", k):
            raise ValueError(f"Ključ nastavitve vsebuje nedovoljene znake: '{k}'")
        return k


class ShizukuCachePayload(BaseModel):
    package: str = Field(..., max_length=128, description="Ime aplikacijskega paketa za vzdrževanje predpomnilnika")

    @field_validator("package")
    @classmethod
    def validate_package(cls, v: str) -> str:
        pkg = v.strip()
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$", pkg):
            raise ValueError(f"Neveljaven format imena paketa: '{pkg}'")
        return pkg


class TypedSafeerAction(BaseModel):
    """
    Imutabilno tipizirano dejanje, ki ga PolicyEngine posreduje Providerju.
    """
    device_id: str
    action: str
    capability: Optional[str] = None
    payload: Optional[BaseModel] = None
    risk_class: RiskClass = RiskClass.SAFE
    is_trusted_device: bool = False
