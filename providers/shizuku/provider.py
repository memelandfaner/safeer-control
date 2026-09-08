"""
Shizuku Privilege Provider za Safeer Control V0.5.1 (Real Shizuku Boundary).
Uveljavlja stroge varnostne meje:
1. Popolna odsotnost zunanjega izvajanja lupinskih ukazov (BREZ exec, subprocess, shell, su, argv).
2. Strukturiran in tipiziran Companion transport protokol.
3. Fail-closed obnašanje: ob kakršnemkoli izpadu povezave ali neavtoriziranem odzivu se operacija nemudoma zavrne.
"""

from typing import Any, Dict, Optional
from core.devices.models import Device, DeviceStatus
from core.actions.models import ActionResult
from providers.base import BaseDeviceProvider
from providers.shizuku.capabilities import Capability, CapabilityGate
from providers.shizuku.transport import (
    BaseCompanionTransport,
    HttpCompanionTransport,
    CompanionRequest,
    CompanionResponse,
)


class ShizukuProvider(BaseDeviceProvider):
    """
    Privilegirani ponudnik za Android naprave prek varnega protokola Safeer Companion.
    Dostopne so izključno 3 vnaprej definirane tipizirane zmožnosti:
    1. force_stop(package_name: str) -> ActionResult
    2. read_setting(namespace: str, key: str) -> ActionResult
    3. clear_cache(package_name: str) -> ActionResult

    V javnem provider contractu in interni kodi eksplicitno NE OBSTAJAJO:
    - subprocess ali klici zunanjih orodij
    - exec(command)
    - shell(string)
    - su(...)
    - poljubni argv ali escape hatchi.
    """

    def __init__(
        self,
        device: Device,
        transport: Optional[BaseCompanionTransport] = None,
        keystore: Optional[Any] = None
    ):
        super().__init__(device)
        self._is_active = True
        companion_port = 8995
        if self.device.port and self.device.port > 0 and self.device.port != 5555:
            companion_port = self.device.port

        from core.security.keystore import get_keystore
        self.keystore = keystore or get_keystore()

        if transport is not None:
            self.transport = transport
        else:
            # Skrivnosti in certifikatni prstni odtis prihajajo izključno iz varnega DeviceKeyStore
            secret = self.keystore.get_key(self.device.id) if self.keystore else None
            tls_fp = self.keystore.get_tls_fingerprint(self.device.id) if self.keystore else None

            self.transport = HttpCompanionTransport(
                host=self.device.host,
                port=companion_port,
                secret_token=secret,
                use_tls=bool(tls_fp),
                pinned_fingerprint=tls_fp,
            )

    def pair_pin(self, pin: str) -> tuple[str, str]:
        """
        V0.8 Interaktivna seznanitev s 6-mestnim PIN-om prek TLS šifrirane povezave.
        Izvede handshake, shrani izpeljani ključ in TLS certifikatni odtis v KeyStore
        ter posodobi transport. Vrne (derived_secret, tls_fingerprint).
        """
        if not hasattr(self, "keystore") or self.keystore is None:
            from core.security.keystore import get_keystore
            self.keystore = get_keystore()

        if not hasattr(self.transport, "handshake_pairing"):
            raise NotImplementedError("Transport ne podpira seznanitve s PIN-om")

        derived_key, tls_fp = self.transport.handshake_pairing(pin)

        # Shrani v varen KeyStore
        self.keystore.set_key(self.device.id, derived_key, tls_fingerprint=tls_fp)
        return derived_key, tls_fp

    def pair(self, secret_token: Optional[str] = None, tls_fingerprint: Optional[str] = None) -> str:
        """Seznani napravo s Safeer KeyStore in uveljavi ključ v transportu."""
        if not hasattr(self, "keystore") or self.keystore is None:
            from core.security.keystore import get_keystore
            self.keystore = get_keystore()

        if secret_token:
            self.keystore.set_key(self.device.id, secret_token, tls_fingerprint=tls_fingerprint)
            key = secret_token
        else:
            key = self.keystore.get_or_create_key(self.device.id, tls_fingerprint=tls_fingerprint)

        if hasattr(self.transport, "secret_token"):
            self.transport.secret_token = key
        if tls_fingerprint and hasattr(self.transport, "pinned_fingerprint"):
            self.transport.pinned_fingerprint = tls_fingerprint.lower()
            self.transport.use_tls = True
        return key

    def rotate_secret(self) -> str:
        """Rotira 256-bitni ključ naprave v KeyStore in nemudoma posodobi transport."""
        if not hasattr(self, "keystore") or self.keystore is None:
            from core.security.keystore import get_keystore
            self.keystore = get_keystore()

        new_key = self.keystore.rotate_key(self.device.id)
        if hasattr(self.transport, "secret_token"):
            self.transport.secret_token = new_key
        return new_key

    def connect(self) -> bool:
        self._is_active = True
        return True

    def disconnect(self) -> None:
        self._is_active = False

    def update_target(self, new_host: str, new_port: int) -> None:
        self.device.host = new_host
        self.device.port = new_port
        if hasattr(self.transport, "host"):
            self.transport.host = new_host

    def get_status(self) -> DeviceStatus:
        is_healthy = self._is_active
        if hasattr(self.transport, "check_health"):
            is_healthy = self.transport.check_health()

        extra = {
            "shizuku_privileged": is_healthy,
            "transport": self.transport.__class__.__name__,
            "tls_enabled": getattr(self.transport, "use_tls", False),
            "tls_pinned": bool(getattr(self.transport, "pinned_fingerprint", None)),
            "supported_capabilities": [
                Capability.APP_FORCE_STOP.value,
                Capability.SETTINGS_READ.value,
                Capability.APP_CACHE_MAINTENANCE.value,
            ]
        }
        return DeviceStatus(
            online=is_healthy,
            latency_ms=0.5 if is_healthy else -1.0,
            extra=extra
        )

    def get_lifecycle_status(self) -> Dict[str, Any]:
        """Pridobi strukturirano poročilo o življenjskem ciklu Companion storitve."""
        if hasattr(self.transport, "get_lifecycle"):
            lc = self.transport.get_lifecycle()
            if lc:
                return lc.model_dump()
        status = self.get_status()
        return {
            "status": "ok" if status.online else "degraded",
            "version": "0.9.0",
            "protocol_version": "1.1",
            "companion_running": status.online,
            "shizuku_available": status.online,
            "shizuku_permission_granted": status.online,
            "shizuku_state": "ready" if status.online else "waiting_for_shizuku",
            "tls_enabled": status.extra.get("tls_enabled", False),
            "tls_fingerprint": getattr(self.transport, "pinned_fingerprint", None),
            "supported_capabilities": status.extra.get("supported_capabilities", []),
        }

    def update_companion(self, binary_bytes: bytes, restart: bool = True) -> Dict[str, Any]:
        """Izvede nadzorovano posodobitev (OTA) Companion binarnega programa."""
        if not hasattr(self.transport, "update_companion"):
            return {"success": False, "error_message": "Transport ne podpira posodobitev"}
        res = self.transport.update_companion(binary_bytes=binary_bytes, restart=restart)
        return res.model_dump()

    # =========================================================================
    # 1. TIPIZIRANA ZMOŽNOST: APP_FORCE_STOP
    # =========================================================================
    def force_stop(self, package_name: str) -> ActionResult:
        """Varna zaustavitev odobrenega paketa preko Companion transporta."""
        ok, reason = CapabilityGate.require(Capability.APP_FORCE_STOP, {"package": package_name})
        if not ok:
            return ActionResult(
                success=False,
                device_id=self.device.id,
                action=Capability.APP_FORCE_STOP.value,
                message=f"CapabilityGate zavrnil zahtevo: {reason}"
            )

        req = CompanionRequest(
            capability=Capability.APP_FORCE_STOP,
            params={"package": package_name},
            token_hash=getattr(self.device.identity, "auth_token_hash", None)
        )
        resp: CompanionResponse = self.transport.send(req)

        return ActionResult(
            success=resp.success,
            device_id=self.device.id,
            action=Capability.APP_FORCE_STOP.value,
            message=resp.error_message if not resp.success else f"Aplikacija '{package_name}' je bila uspešno ustavljena preko Companiona.",
            data=resp.data or {"package": package_name}
        )

    # =========================================================================
    # 2. TIPIZIRANA ZMOŽNOST: SETTINGS_READ
    # =========================================================================
    def read_setting(self, namespace: str, key: str) -> ActionResult:
        """Varno branje odobrene sistemske nastavitve preko Companion transporta."""
        ok, reason = CapabilityGate.require(Capability.SETTINGS_READ, {"namespace": namespace, "key": key})
        if not ok:
            return ActionResult(
                success=False,
                device_id=self.device.id,
                action=Capability.SETTINGS_READ.value,
                message=f"CapabilityGate zavrnil zahtevo: {reason}"
            )

        req = CompanionRequest(
            capability=Capability.SETTINGS_READ,
            params={"namespace": namespace, "key": key},
            token_hash=getattr(self.device.identity, "auth_token_hash", None)
        )
        resp: CompanionResponse = self.transport.send(req)

        return ActionResult(
            success=resp.success,
            device_id=self.device.id,
            action=Capability.SETTINGS_READ.value,
            message=resp.error_message if not resp.success else f"Nastavitev {namespace}.{key} prebrana preko Companiona.",
            data=resp.data or {"namespace": namespace, "key": key}
        )

    # =========================================================================
    # 3. TIPIZIRANA ZMOŽNOST: APP_CACHE_MAINTENANCE
    # =========================================================================
    def clear_cache(self, package_name: str) -> ActionResult:
        """Varno vzdrževanje predpomnilnika odobrenega paketa preko Companion transporta."""
        ok, reason = CapabilityGate.require(Capability.APP_CACHE_MAINTENANCE, {"package": package_name})
        if not ok:
            return ActionResult(
                success=False,
                device_id=self.device.id,
                action=Capability.APP_CACHE_MAINTENANCE.value,
                message=f"CapabilityGate zavrnil zahtevo: {reason}"
            )

        req = CompanionRequest(
            capability=Capability.APP_CACHE_MAINTENANCE,
            params={"package": package_name},
            token_hash=getattr(self.device.identity, "auth_token_hash", None)
        )
        resp: CompanionResponse = self.transport.send(req)

        return ActionResult(
            success=resp.success,
            device_id=self.device.id,
            action=Capability.APP_CACHE_MAINTENANCE.value,
            message=resp.error_message if not resp.success else f"Predpomnilnik aplikacije '{package_name}' očiščen preko Companiona.",
            data=resp.data or {"package": package_name}
        )

    # =========================================================================
    # SPLOŠNI DISPATCHER ZAHTEV
    # =========================================================================
    def execute_action(self, action: str, params: Dict[str, Any]) -> ActionResult:
        act = action.lower().strip()
        if act in ("app_force_stop", "force_stop", "app.force_stop"):
            pkg = str(params.get("package", "")).strip()
            return self.force_stop(pkg)

        elif act in ("settings_read", "read_setting", "settings.read"):
            ns = str(params.get("namespace", "global")).strip().lower()
            key = str(params.get("key", "")).strip()
            return self.read_setting(ns, key)

        elif act in ("app_cache_maintenance", "clear_cache", "app.cache_maintenance"):
            pkg = str(params.get("package", "")).strip()
            return self.clear_cache(pkg)

        elif act in ("status", "ping"):
            stat = self.get_status()
            return ActionResult(
                success=stat.online,
                device_id=self.device.id,
                action=action,
                message="Shizuku Companion aktiven" if stat.online else "Shizuku Companion ni dosegljiv",
                data={"online": stat.online}
            )

        return ActionResult(
            success=False,
            device_id=self.device.id,
            action=action,
            message=f"Dejanje '{action}' ni podprto v ShizukuProviderju. Poljubni ukazi so prepovedani."
        )
