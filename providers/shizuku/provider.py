"""
Shizuku Privilege Provider za Safeer Control V0.5.
Uveljavlja temeljno varnostno načelo:
ShizukuProvider nima API-ja za poljubne ukaze (BREZ exec, BREZ shell, BREZ su, BREZ raw argv).
Vse operacije so strogo tipizirane in predhodno avtorizirane skozi CapabilityGate.
"""

import subprocess
from typing import Any, Dict, Optional
from core.devices.models import Device, DeviceStatus
from core.actions.models import ActionResult
from providers.base import BaseDeviceProvider
from providers.shizuku.capabilities import Capability, CapabilityGate


class ShizukuProvider(BaseDeviceProvider):
    """
    Privilegirani ponudnik za Android naprave prek Shizuku / Safeer Companion.
    Dostopne so izključno 3 vnaprej definirane tipizirane zmožnosti:
    1. force_stop(package_name: str) -> ActionResult
    2. read_setting(namespace: str, key: str) -> ActionResult
    3. clear_cache(package_name: str) -> ActionResult

    V javnem provider contractu eksplicitno NE OBSTAJAJO:
    - exec(command)
    - shell(string)
    - su(...)
    - poljubni argv ali escape hatchi.
    """

    def __init__(self, device: Device):
        super().__init__(device)
        self._is_active = True
        self.target = f"{self.device.host}:{self.device.port}" if self.device.port > 0 else self.device.host

    def connect(self) -> bool:
        self._is_active = True
        return True

    def disconnect(self) -> None:
        self._is_active = False

    def update_target(self, new_host: str, new_port: int) -> None:
        self.device.host = new_host
        self.device.port = new_port
        self.target = f"{new_host}:{new_port}" if new_port > 0 else new_host

    def get_status(self) -> DeviceStatus:
        return DeviceStatus(
            online=self._is_active,
            latency_ms=0.2 if self._is_active else -1.0,
            extra={
                "shizuku_privileged": self._is_active,
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
        """Varna zaustavitev odobrenega paketa brez lupinskega posrednika."""
        ok, reason = CapabilityGate.require(Capability.APP_FORCE_STOP, {"package": package_name})
        if not ok:
            return ActionResult(
                success=False,
                device_id=self.device.id,
                action=Capability.APP_FORCE_STOP.value,
                message=f"CapabilityGate zavrnil zahtevo: {reason}"
            )

        try:
            # Izvedba prek varnega seznama argumentov (BREZ shell=True!)
            cmd = ["adb"]
            if self.target and self.target != "127.0.0.1":
                cmd.extend(["-s", self.target])
            cmd.extend(["shell", "am", "force-stop", package_name])

            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5.0)
            if res.returncode == 0:
                return ActionResult(
                    success=True,
                    device_id=self.device.id,
                    action=Capability.APP_FORCE_STOP.value,
                    message=f"Aplikacija '{package_name}' je bila uspešno ustavljena.",
                    data={"package": package_name}
                )
            return ActionResult(
                success=False,
                device_id=self.device.id,
                action=Capability.APP_FORCE_STOP.value,
                message=f"Napaka pri zaustavitvi: {res.stderr.strip() or res.stdout.strip()}"
            )
        except Exception as e:
            return ActionResult(
                success=False,
                device_id=self.device.id,
                action=Capability.APP_FORCE_STOP.value,
                message=f"Izjema pri klicu force_stop: {e}"
            )

    # =========================================================================
    # 2. TIPIZIRANA ZMOŽNOST: SETTINGS_READ
    # =========================================================================
    def read_setting(self, namespace: str, key: str) -> ActionResult:
        """Varno branje odobrene sistemske nastavitve brez lupinskega posrednika."""
        ok, reason = CapabilityGate.require(Capability.SETTINGS_READ, {"namespace": namespace, "key": key})
        if not ok:
            return ActionResult(
                success=False,
                device_id=self.device.id,
                action=Capability.SETTINGS_READ.value,
                message=f"CapabilityGate zavrnil zahtevo: {reason}"
            )

        try:
            cmd = ["adb"]
            if self.target and self.target != "127.0.0.1":
                cmd.extend(["-s", self.target])
            cmd.extend(["shell", "settings", "get", namespace, key])

            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=3.0)
            val = res.stdout.strip() if res.returncode == 0 else ""
            return ActionResult(
                success=res.returncode == 0,
                device_id=self.device.id,
                action=Capability.SETTINGS_READ.value,
                message=f"Nastavitev {namespace}.{key} prebrana: {val}",
                data={"namespace": namespace, "key": key, "value": val}
            )
        except Exception as e:
            return ActionResult(
                success=False,
                device_id=self.device.id,
                action=Capability.SETTINGS_READ.value,
                message=f"Izjema pri branju nastavitve: {e}"
            )

    # =========================================================================
    # 3. TIPIZIRANA ZMOŽNOST: APP_CACHE_MAINTENANCE
    # =========================================================================
    def clear_cache(self, package_name: str) -> ActionResult:
        """Varno vzdrževanje predpomnilnika odobrenega paketa."""
        ok, reason = CapabilityGate.require(Capability.APP_CACHE_MAINTENANCE, {"package": package_name})
        if not ok:
            return ActionResult(
                success=False,
                device_id=self.device.id,
                action=Capability.APP_CACHE_MAINTENANCE.value,
                message=f"CapabilityGate zavrnil zahtevo: {reason}"
            )

        try:
            cmd = ["adb"]
            if self.target and self.target != "127.0.0.1":
                cmd.extend(["-s", self.target])
            cmd.extend(["shell", "pm", "clear", package_name])

            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5.0)
            is_success = "success" in res.stdout.lower() or res.returncode == 0
            return ActionResult(
                success=is_success,
                device_id=self.device.id,
                action=Capability.APP_CACHE_MAINTENANCE.value,
                message=f"Predpomnilnik aplikacije '{package_name}' očiščen.",
                data={"package": package_name}
            )
        except Exception as e:
            return ActionResult(
                success=False,
                device_id=self.device.id,
                action=Capability.APP_CACHE_MAINTENANCE.value,
                message=f"Izjema pri čiščenju predpomnilnika: {e}"
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
            return ActionResult(
                success=True,
                device_id=self.device.id,
                action=action,
                message="Shizuku Companion aktiven",
                data={"online": self._is_active}
            )

        return ActionResult(
            success=False,
            device_id=self.device.id,
            action=action,
            message=f"Dejanje '{action}' ni podprto v ShizukuProviderju. Poljubni ukazi so prepovedani."
        )
