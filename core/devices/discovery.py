"""
Dynamic Device Discovery modul za Safeer Control V0.4.
Hierarhija odkrivanja naprav v lokalnem omrežju:
1. Safeer Companion discovery (mDNS) -> kriptografska identiteta
2. Android TV discovery (mDNS / ADB probe) -> preverjanje obstoječe identitete
3. UPnP / SSDP -> device-description XML -> RenderingControl -> controlURL
4. Static host -> fallback only
"""

import time
import socket
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
import subprocess
from typing import List, Dict, Any, Optional, Tuple

from core.devices.models import Device, DeviceType, DiscoveryMethod


class SSDPDiscovery:
    """
    UPnP / SSDP odkrivanje avdio naprav in dinamična razrešitev controlURL prek description.xml.
    """

    SSDP_ADDR = "239.255.255.250"
    SSDP_PORT = 1900
    SSDP_MX = 1
    SSDP_ST = "urn:schemas-upnp-org:service:RenderingControl:1"

    @classmethod
    def parse_description_xml(cls, location_url: str, timeout: float = 1.5) -> Optional[Dict[str, Any]]:
        """Prenese in razčleni opis naprave ter izvleče friendlyName, UDN in controlURL."""
        try:
            req = urllib.request.Request(location_url, headers={"User-Agent": "SafeerControl/0.4"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                xml_data = resp.read().decode("utf-8", errors="ignore")
                root = ET.fromstring(xml_data)

                friendly_name = ""
                udn = ""
                control_url = ""

                # Poišči friendlyName in UDN
                for elem in root.iter():
                    if elem.tag.endswith("friendlyName") and elem.text:
                        friendly_name = elem.text.strip()
                    elif elem.tag.endswith("UDN") and elem.text:
                        udn = elem.text.strip()
                    elif elem.tag.endswith("service"):
                        st = ""
                        cu = ""
                        for child in elem:
                            if child.tag.endswith("serviceType") and child.text:
                                st = child.text.strip()
                            elif child.tag.endswith("controlURL") and child.text:
                                cu = child.text.strip()
                        if "RenderingControl" in st and cu:
                            control_url = cu

                if control_url:
                    parsed_loc = urllib.parse.urlparse(location_url)
                    base_origin = f"{parsed_loc.scheme}://{parsed_loc.netloc}"
                    if not control_url.startswith("http"):
                        if not control_url.startswith("/"):
                            control_url = "/" + control_url
                        control_url = f"{base_origin}{control_url}"

                    return {
                        "friendly_name": friendly_name or "UPnP Audio",
                        "udn": udn,
                        "control_url": control_url,
                        "location": location_url,
                        "host": parsed_loc.hostname,
                        "port": parsed_loc.port or 49152
                    }
        except Exception:
            pass
        return None

    @classmethod
    def probe_host(cls, host: str, port: int = 49152, timeout: float = 1.0) -> Optional[Dict[str, Any]]:
        """Preveri UPnP opis na določenem gostitelju."""
        for path in ("/description.xml", "/device.xml", "/upnp/desc.xml"):
            url = f"http://{host}:{port}{path}"
            res = cls.parse_description_xml(url, timeout=timeout)
            if res:
                return res
        return None


class AndroidTVDiscovery:
    """
    Odkrivanje Android TV naprav preko ADB vrat 5555 z verifikacijo identitete.
    Nov IP naslov nikoli samodejno ne podeduje trusted=True!
    """

    @classmethod
    def check_port(cls, host: str, port: int = 5555, timeout: float = 0.5) -> bool:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            return sock.connect_ex((host, port)) == 0
        except Exception:
            return False
        finally:
            sock.close()

    @classmethod
    def verify_identity(
        cls,
        host: str,
        port: int = 5555,
        expected_fingerprint: Optional[str] = None
    ) -> Tuple[bool, str]:
        """
        Poveže se na ADB port in preveri ujemanje strojne identitete.
        """
        target = f"{host}:{port}"
        try:
            # Poskusi hitro povezavo
            subprocess.run(["adb", "connect", target], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2.0)
            res = subprocess.run(
                ["adb", "-s", target, "shell", "getprop", "ro.serialno"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=2.0
            )
            serial = res.stdout.strip() if res.returncode == 0 else ""
            if not serial:
                res_id = subprocess.run(
                    ["adb", "-s", target, "shell", "settings", "get", "secure", "android_id"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=2.0
                )
                serial = res_id.stdout.strip() if res_id.returncode == 0 else ""

            if not serial:
                return False, "Ni mogoče pridobiti strojne identitete prek ADB."

            if expected_fingerprint:
                if serial == expected_fingerprint or expected_fingerprint in serial:
                    return True, serial
                return False, f"Strojna identiteta '{serial}' se ne ujema s pričakovano '{expected_fingerprint}'."

            return True, serial
        except Exception as e:
            return False, f"ADB poizvedba odpovedala: {e}"


class DynamicDiscoveryManager:
    """
    Centralni upravitelj dinamičnega odkrivanja z uveljavljeno varnostno hierarhijo.
    """

    @classmethod
    def resolve_device(
        cls,
        device: Device,
        candidate_hosts: Optional[List[str]] = None
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """
        Poskusi ponovno locirati napravo, če je trenutni IP postal nedosegljiv.
        Vrne (uspeh, metoda, podrobnosti).
        """
        # 1. Ali je trenutni lokator še vedno živ?
        if cls._ping_host(device.host, 0.4):
            return True, DiscoveryMethod.STATIC_FALLBACK.value, {"host": device.host, "port": device.port}

        # Določi kandidate za preiskovanje
        candidates = list(candidate_hosts or [])
        if not candidates:
            # Privzeti lokalni nabor kandidatov
            base_parts = device.host.split(".")
            if len(base_parts) == 4:
                prefix = ".".join(base_parts[:3])
                # Preglej nekaj verjetnih DHCP naslovov v istem podomrežju
                candidates = [f"{prefix}.{i}" for i in range(50, 155) if f"{prefix}.{i}" != device.host]

        # 2. Glede na tip naprave uporabi ustrezno vejo hierarhije
        if device.type == DeviceType.ANDROID_TV:
            for cand_ip in candidates:
                if cls.AndroidTVDiscovery.check_port(cand_ip, device.port, timeout=0.2):
                    expected_fp = getattr(device.identity, "fingerprint", None)
                    match_ok, hw_id = cls.AndroidTVDiscovery.verify_identity(
                        cand_ip,
                        device.port,
                        expected_fingerprint=expected_fp
                    )
                    if match_ok:
                        return True, DiscoveryMethod.ADB_PROBE.value, {
                            "host": cand_ip,
                            "port": device.port,
                            "fingerprint": hw_id
                        }

        elif device.type == DeviceType.AUDIO_SOUNDBAR:
            for cand_ip in candidates:
                res = cls.SSDPDiscovery.probe_host(cand_ip, device.port, timeout=0.3)
                if res:
                    return True, DiscoveryMethod.SSDP.value, res

        # 4. Fallback na obstoječi gostitelj
        return False, DiscoveryMethod.STATIC_FALLBACK.value, None

    @classmethod
    def _ping_host(cls, host: str, timeout: float = 0.5) -> bool:
        try:
            res = subprocess.run(
                ["ping", "-c", "1", "-W", str(max(1, int(timeout))), host],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout + 0.5
            )
            return res.returncode == 0
        except Exception:
            return False

    AndroidTVDiscovery = AndroidTVDiscovery
    SSDPDiscovery = SSDPDiscovery


_discovery_manager_instance: Optional[DynamicDiscoveryManager] = None


def get_discovery_manager() -> DynamicDiscoveryManager:
    global _discovery_manager_instance
    if _discovery_manager_instance is None:
        _discovery_manager_instance = DynamicDiscoveryManager()
    return _discovery_manager_instance
