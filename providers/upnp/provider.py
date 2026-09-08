"""
UPnP Audio Provider (JBL Bar 300 / DLNA RenderingControl).
V0.4: Dinamična izpeljava controlURL prek SSDP opisa (description XML)
in hardware-aware zaščita za preprečevanje utripanja HDMI-CEC zvoka.
"""

import time
import re
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
from typing import Any, Dict, Optional
from core.devices.models import Device, DeviceStatus
from core.actions.models import ActionResult
from providers.base import BaseDeviceProvider


class UPnPProvider(BaseDeviceProvider):
    def __init__(self, device: Device, control_url: Optional[str] = None):
        super().__init__(device)
        self.endpoint = control_url or self._resolve_control_url()
        self._cache_time = 0.0
        self._cached_status: Optional[DeviceStatus] = None

    def update_target(self, new_host: str, new_port: int, control_url: Optional[str] = None) -> None:
        """Posodobi ciljni IP/vrata ob dinamičnem odkrivanju (DHCP resilience)."""
        self.device.host = new_host
        self.device.port = new_port
        self.endpoint = control_url or self._resolve_control_url()
        self._cached_status = None
        self._cache_time = 0.0

    def _resolve_control_url(self) -> str:
        """Dinamično prebere description.xml in poišče dejanski controlURL za RenderingControl."""
        fallback = f"http://{self.device.host}:{self.device.port}/upnp/control/rendercontrol1"
        for desc_path in ("/description.xml", "/device.xml", "/upnp/desc.xml"):
            url = f"http://{self.device.host}:{self.device.port}{desc_path}"
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "SafeerControl/0.4"})
                with urllib.request.urlopen(req, timeout=1.2) as resp:
                    xml_content = resp.read().decode("utf-8", errors="ignore")
                    root = ET.fromstring(xml_content)
                    for elem in root.iter():
                        if elem.tag.endswith("service"):
                            service_type = ""
                            ctrl_url = ""
                            for child in elem:
                                if child.tag.endswith("serviceType") and child.text:
                                    service_type = child.text.strip()
                                elif child.tag.endswith("controlURL") and child.text:
                                    ctrl_url = child.text.strip()
                            if "RenderingControl" in service_type and ctrl_url:
                                if ctrl_url.startswith("http"):
                                    return ctrl_url
                                elif ctrl_url.startswith("/"):
                                    return f"http://{self.device.host}:{self.device.port}{ctrl_url}"
                                else:
                                    return f"http://{self.device.host}:{self.device.port}/{ctrl_url}"
            except Exception:
                continue
        return fallback

    def connect(self) -> bool:
        lat = self.ping(1.0)
        return lat >= 0

    def disconnect(self) -> None:
        pass

    def _soap_request(self, action: str, body: str, timeout: float = 2.0) -> str:
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
                self._cache_time = 0.0
                return ActionResult(
                    success=ok,
                    device_id=self.device.id,
                    action=action,
                    message=f"Glasnost nastavljena na {vol} %" if ok else f"Napaka pri nastavitvi: {res}",
                    data={"volume": vol},
                    elapsed_ms=(time.time() - t0) * 1000
                )

            elif action == "unmute":
                cur_stat = self.get_status()
                if cur_stat.muted is False:
                    return ActionResult(
                        success=True,
                        device_id=self.device.id,
                        action=action,
                        message="Zvočnik je že aktiven (brez ponovnega odmutiranja)",
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

            elif action == "volume_up":
                cur_stat = self.get_status()
                cur_vol = cur_stat.volume if (cur_stat.volume is not None and cur_stat.volume >= 0) else 30
                step = params.get("step", 5)
                target_vol = min(100, cur_vol + step)
                res = self._soap_request("SetVolume", f"<Channel>Master</Channel><DesiredVolume>{target_vol}</DesiredVolume>")
                ok = "SetVolumeResponse" in res
                self._cache_time = 0.0
                return ActionResult(
                    success=ok,
                    device_id=self.device.id,
                    action=action,
                    message=f"Glasnost povečana na {target_vol} %" if ok else f"Napaka: {res}",
                    data={"volume": target_vol},
                    elapsed_ms=(time.time() - t0) * 1000
                )

            elif action == "volume_down":
                cur_stat = self.get_status()
                cur_vol = cur_stat.volume if (cur_stat.volume is not None and cur_stat.volume >= 0) else 30
                step = params.get("step", 5)
                target_vol = max(0, cur_vol - step)
                res = self._soap_request("SetVolume", f"<Channel>Master</Channel><DesiredVolume>{target_vol}</DesiredVolume>")
                ok = "SetVolumeResponse" in res
                self._cache_time = 0.0
                return ActionResult(
                    success=ok,
                    device_id=self.device.id,
                    action=action,
                    message=f"Glasnost znižana na {target_vol} %" if ok else f"Napaka: {res}",
                    data={"volume": target_vol},
                    elapsed_ms=(time.time() - t0) * 1000
                )

            elif action == "toggle_mute":
                cur_stat = self.get_status()
                if cur_stat.muted:
                    return self.execute_action("unmute", params)
                else:
                    return self.execute_action("mute", params)

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
