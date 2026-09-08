"""
JBL Audio Provider (UPnP / DLNA / SOAP) za Safeer Control.
Strojno-zavedna koda (Hardware-aware) skladno z GEMINI.md:
- Preprečuje periodično ponavljanje SetMute/ADJUST_UNMUTE (sindrom utripanja JBL Bar 300 HDMI-CEC).
- Odmute se izvede samo ob resničnem stanju utišanosti.
"""

import time
import re
import urllib.request
import urllib.error
from typing import Any, Dict
from safeer_control.core.models import Device, DeviceStatus, ActionResult
from safeer_control.providers.base import BaseDeviceProvider


class JBLAudioProvider(BaseDeviceProvider):
    def __init__(self, device: Device):
        super().__init__(device)
        self.endpoint = f"http://{self.device.host}:{self.device.port}/upnp/control/rendercontrol1"
        self._cache_time = 0.0
        self._cached_status: Optional[DeviceStatus] = None

    def connect(self) -> bool:
        """Preveri odzivnost UPnP vmesnika zvočnika."""
        lat = self.ping(1.0)
        return lat >= 0

    def disconnect(self) -> None:
        pass

    def _soap_request(self, action: str, body: str, timeout: float = 2.0) -> str:
        """Pošlje standardni UPnP SOAP zahtevek na RenderingControl."""
        soap_envelope = f"""<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
    <s:Body>
        <u:{action} xmlns:u="urn:schemas-upnp-org:service:RenderingControl:1">
            <InstanceID>0</InstanceID>
            {body}
        </u:{action}>
    </s:Body>
</s:Envelope>"""
        req = urllib.request.Request(
            self.endpoint,
            data=soap_envelope.encode("utf-8"),
            headers={
                "Content-Type": "text/xml; charset=\"utf-8\"",
                "SOAPAction": f"\"urn:schemas-upnp-org:service:RenderingControl:1#{action}\""
            }
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode("utf-8")
        except Exception as e:
            return f"ERROR: {e}"

    def get_status(self) -> DeviceStatus:
        """Pridobi trenutno glasnost in stanje utišanja z medpomnilnikom."""
        now = time.time()
        if self._cached_status and (now - self._cache_time < 2.5):
            return self._cached_status

        lat = self.ping(1.0)
        if lat < 0:
            stat = DeviceStatus(online=False, latency_ms=-1.0)
            self._cached_status = stat
            self._cache_time = now
            return stat

        vol_res = self._soap_request("GetVolume", "<Channel>Master</Channel>")
        mute_res = self._soap_request("GetMute", "<Channel>Master</Channel>")

        vol_m = re.search(r"<CurrentVolume>(\d+)</CurrentVolume>", vol_res)
        mute_m = re.search(r"<CurrentMute>(\d+)</CurrentMute>", mute_res)

        vol = int(vol_m.group(1)) if vol_m else -1
        is_muted = (mute_m.group(1) == "1") if mute_m else False

        stat = DeviceStatus(
            online=vol >= 0,
            latency_ms=lat,
            volume=vol if vol >= 0 else None,
            muted=is_muted,
            extra={"upnp_endpoint": self.endpoint}
        )
        self._cached_status = stat
        self._cache_time = now
        return stat

    def execute_action(self, action: str, params: Dict[str, Any]) -> ActionResult:
        t0 = time.time()
        action = action.lower().strip()

        try:
            if action == "status":
                stat = self.get_status()
                return ActionResult(
                    success=stat.online,
                    device_id=self.device.id,
                    action=action,
                    message="Avdio status osvežen",
                    data=stat.model_dump(),
                    elapsed_ms=(time.time() - t0) * 1000
                )

            elif action in ("volume", "set_volume"):
                vol = int(params.get("volume", 20))
                vol = max(0, min(100, vol))
                res = self._soap_request("SetVolume", f"<Channel>Master</Channel><DesiredVolume>{vol}</DesiredVolume>")
                ok = "SetVolumeResponse" in res
                self._cache_time = 0.0  # Ponastavi predpomnilnik
                return ActionResult(
                    success=ok,
                    device_id=self.device.id,
                    action=action,
                    message=f"Glasnost nastavljena na {vol} %" if ok else f"Napaka pri nastavitvi glasnosti: {res}",
                    data={"volume": vol},
                    elapsed_ms=(time.time() - t0) * 1000
                )

            elif action == "unmute":
                # Hardware-aware: najprej preveri ali je res utišan, da ne kvari HDMI-CEC pretoka
                cur_stat = self.get_status()
                if cur_stat.muted is False:
                    return ActionResult(
                        success=True,
                        device_id=self.device.id,
                        action=action,
                        message="Zvočnik je že aktiven (ni potrebe po ponovnem odmutu)",
                        elapsed_ms=(time.time() - t0) * 1000
                    )
                res = self._soap_request("SetMute", "<Channel>Master</Channel><DesiredMute>0</DesiredMute>")
                ok = "SetMuteResponse" in res
                self._cache_time = 0.0
                return ActionResult(
                    success=ok,
                    device_id=self.device.id,
                    action=action,
                    message="Zvočnik vklopljen (unmute)" if ok else f"Napaka: {res}",
                    elapsed_ms=(time.time() - t0) * 1000
                )

            elif action == "mute":
                res = self._soap_request("SetMute", "<Channel>Master</Channel><DesiredMute>1</DesiredMute>")
                ok = "SetMuteResponse" in res
                self._cache_time = 0.0
                return ActionResult(
                    success=ok,
                    device_id=self.device.id,
                    action=action,
                    message="Zvočnik utišan (mute)" if ok else f"Napaka: {res}",
                    elapsed_ms=(time.time() - t0) * 1000
                )

            return ActionResult(
                success=False,
                device_id=self.device.id,
                action=action,
                message=f"Neznano avdio dejanje: {action}",
                elapsed_ms=(time.time() - t0) * 1000
            )
        except Exception as e:
            return ActionResult(
                success=False,
                device_id=self.device.id,
                action=action,
                message=f"Napaka pri izvajanju avdio ukaza: {e}",
                elapsed_ms=(time.time() - t0) * 1000
            )
