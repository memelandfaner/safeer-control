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
            # Skrivnosti prihajajo izključno iz varnega DeviceKeyStore
            secret = self.keystore.get_key(self.device.id) if self.keystore else None

            self.transport = HttpCompanionTransport(
                host=self.device.host,
                port=companion_port,
                secret_token=secret
            )

    def pair(self, secret_token: Optional[str] = None) -> str:
        """Seznani napravo s Safeer KeyStore in uveljavi ključ v transportu."""
        if not hasattr(self, "keystore") or self.keystore is None:
            from core.security.keystore import get_keystore
            self.keystore = get_keystore()

        if secret_token:
            self.keystore.set_key(self.device.id, secret_token)
            key = secret_token
        else:
            key = self.keystore.get_or_create_key(self.device.id)

        if hasattr(self.transport, "secret_token"):
            self.transport.secret_token = key
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

        return DeviceStatus(
            online=is_healthy,
            latency_ms=0.5 if is_healthy else -1.0,
            extra={
                "shizuku_privileged": is_healthy,
                "transport": self.transport.__class__.__name__,
                "supported_capabilities": [
                    Capability.APP_FORCE_STOP.value,
                    Capability.SETTINGS_READ.value,
                    Capability.APP_CACHE_MAINTENANCE.value,
                ]
            }
        )

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
