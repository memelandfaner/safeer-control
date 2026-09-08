"""
Dynamic Device Discovery modul za Safeer Control V0.4.1.
Hierarhija odkrivanja naprav v lokalnem omrežju:
1. DiscoveryCache (TTL 60s - preprečevanje omrežnega poplavljanja)
2. mDNS Discovery (_safeer._tcp.local / _adb._tcp.local) -> primarno odkrivanje
3. SSDP / UPnP Multicast M-SEARCH (239.255.255.250:1900) -> RenderingControl XML parser
4. Strojno preverjanje identitete (hardware_fingerprint) -> nov IP NIKOLI samodejno ne podeduje zaupanja!
5. Subnet probing -> izključno kot zadnji zasilni izhod (fallback)
"""

import time
import socket
import urllib.request
import urllib.error
import urllib.parse
import xml.etree.ElementTree as ET
import subprocess
from typing import List, Dict, Any, Optional, Tuple

from core.devices.models import Device, DeviceType, DiscoveryMethod


class DiscoveryCache:
    """
    Predpomnilnik odkritih naprav z nastavljivim TTL (privzeto 60s).
    Preprečuje omrežno poplavljanje in ponavljajoče poizvedbe ob kratkotrajnih prekinitvah.
    """

    def __init__(self, ttl_seconds: float = 60.0):
        self.ttl = ttl_seconds
        self._cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        if key in self._cache:
            ts, val = self._cache[key]
            if time.time() - ts < self.ttl:
                return val
            del self._cache[key]
        return None

    def set(self, key: str, val: Dict[str, Any]) -> None:
        self._cache[key] = (time.time(), val)

    def invalidate(self, key: str) -> None:
        self._cache.pop(key, None)

    def clear(self) -> None:
        self._cache.clear()


class SSDPDiscovery:
    """
    UPnP / SSDP odkrivanje avdio naprav in dinamična razrešitev controlURL prek description.xml.
    Uporablja pravi UDP multicast M-SEARCH in usmerjeno poizvedovanje.
    """

    SSDP_ADDR = "239.255.255.250"
    SSDP_PORT = 1900
    SSDP_MX = 1
    SSDP_ST = "urn:schemas-upnp-org:service:RenderingControl:1"

    @classmethod
    def parse_description_xml(cls, location_url: str, timeout: float = 1.5) -> Optional[Dict[str, Any]]:
        """Prenese in razčleni opis naprave ter izvleče friendlyName, UDN in controlURL."""
        try:
            req = urllib.request.Request(location_url, headers={"User-Agent": "SafeerControl/0.4.1"})
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
    def multicast_msearch(
        cls,
        search_target: Optional[str] = None,
        timeout: float = 1.5
    ) -> List[Dict[str, Any]]:
        """
        Odda pravi SSDP M-SEARCH multicast UDP paket na 239.255.255.250:1900,
        posluša unicast odgovore naprav in razčleni description.xml iz LOCATION glave.
        """
        target = search_target or cls.SSDP_ST
        results: List[Dict[str, Any]] = []
        msg = (
            f"M-SEARCH * HTTP/1.1\r\n"
            f"HOST: {cls.SSDP_ADDR}:{cls.SSDP_PORT}\r\n"
            f'MAN: "ssdp:discover"\r\n'
            f"MX: {cls.SSDP_MX}\r\n"
            f"ST: {target}\r\n"
            f"\r\n"
        ).encode("utf-8")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        try:
            sock.settimeout(timeout)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.sendto(msg, (cls.SSDP_ADDR, cls.SSDP_PORT))

            seen_locations = set()
            deadline = time.time() + timeout
            while time.time() < deadline:
                remaining = max(0.1, deadline - time.time())
                sock.settimeout(remaining)
                try:
                    data, _ = sock.recvfrom(4096)
                    resp_text = data.decode("utf-8", errors="ignore")
                    location = None
                    for line in resp_text.splitlines():
                        if line.upper().startswith("LOCATION:"):
                            location = line.split(":", 1)[1].strip()
                            break
                    if location and location not in seen_locations:
                        seen_locations.add(location)
                        parsed = cls.parse_description_xml(location, timeout=1.0)
                        if parsed:
                            results.append(parsed)
                except socket.timeout:
                    break
                except Exception:
                    break
        except Exception:
            pass
        finally:
            sock.close()

        return results

    @classmethod
    def probe_host(cls, host: str, port: int = 49152, timeout: float = 1.0) -> Optional[Dict[str, Any]]:
        """Zasilna preveritev UPnP opisa na določenem gostitelju (fallback)."""
        for path in ("/description.xml", "/device.xml", "/upnp/desc.xml"):
            url = f"http://{host}:{port}{path}"
            res = cls.parse_description_xml(url, timeout=timeout)
            if res:
                return res
        return None


class MDNSDiscovery:
    """
    mDNS brskanje po lokalnem omrežju za Safeer Companion (_safeer._tcp.local)
    ali Android TV / ADB (_adb._tcp.local).
    """

    MDNS_ADDR = "224.0.0.251"
    MDNS_PORT = 5353

    @classmethod
    def _build_dns_ptr_query(cls, service_type: str) -> bytes:
        labels = service_type.strip(".").split(".")
        qname = b"".join(bytes([len(l)]) + l.encode("ascii") for l in labels) + b"\x00"
        header = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        footer = b"\x00\x0c\x00\x01"  # Type PTR (12), Class IN (1)
        return header + qname + footer

    @classmethod
    def browse(
        cls,
        service_type: str = "_safeer._tcp.local",
        timeout: float = 1.5
    ) -> List[Dict[str, Any]]:
        """
        Pošlje mDNS PTR multicast povpraševanje na 224.0.0.251:5353 in zbere
        odzivne IP naslove ponudnikov storitve.
        """
        results: List[Dict[str, Any]] = []
        pkt = cls._build_dns_ptr_query(service_type)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        try:
            sock.settimeout(timeout)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
            sock.sendto(pkt, (cls.MDNS_ADDR, cls.MDNS_PORT))

            seen_hosts = set()
            deadline = time.time() + timeout
            while time.time() < deadline:
                remaining = max(0.1, deadline - time.time())
                sock.settimeout(remaining)
                try:
                    data, (src_ip, src_port) = sock.recvfrom(4096)
                    if src_ip not in seen_hosts:
                        seen_hosts.add(src_ip)
                        results.append({
                            "host": src_ip,
                            "port": src_port,
                            "raw_len": len(data),
                            "service": service_type
                        })
                except socket.timeout:
                    break
                except Exception:
                    break
        except Exception:
            pass
        finally:
            sock.close()

        return results


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
        Poveže se na ADB port in preveri ujemanje strojne identitete (hardware_fingerprint).
        """
        target = f"{host}:{port}"
        try:
            # Hitra povezava
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
    Centralni upravitelj dinamičnega odkrivanja z uveljavljeno varnostno hierarhijo:
    0. DiscoveryCache (TTL 60s)
    1. Preverjanje obstoječega lokatorja
    2. Primarno omrežno odkrivanje (mDNS / SSDP Multicast M-SEARCH)
    3. Strojno preverjanje identitete (hardware_fingerprint)
    4. Zasilno preiskovanje kandidatov (Subnet fallback)
    """

    def __init__(self, cache_ttl: float = 60.0):
        self.cache = DiscoveryCache(ttl_seconds=cache_ttl)

    def resolve_device(
        self,
        device: Device,
        candidate_hosts: Optional[List[str]] = None
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """
        Poskusi ponovno locirati napravo, če je trenutni IP postal nedosegljiv.
        Vrne (uspeh, metoda, podrobnosti).
        """
        # 0. Preveri predpomnilnik
        cached = self.cache.get(device.id)
        if cached:
            cached_host = cached.get("host")
            if cached_host and self._ping_host(cached_host, 0.3):
                return True, DiscoveryMethod.CACHE.value, cached

        # 1. Ali je trenutni lokator še vedno dosegljiv?
        if self._ping_host(device.host, 0.4):
            res_info = {"host": device.host, "port": device.port}
            self.cache.set(device.id, res_info)
            return True, DiscoveryMethod.STATIC_FALLBACK.value, res_info

        # 2. Glede na tip naprave uporabi primarno vejo hierarhije
        if device.type == DeviceType.ANDROID_TV:
            expected_fp = device.identity.effective_fingerprint

            # 2a. Primarno: mDNS poizvedba (_safeer._tcp.local in _adb._tcp.local)
            mdns_candidates: List[str] = []
            for srv in ("_safeer._tcp.local", "_adb._tcp.local"):
                for entry in self.MDNSDiscovery.browse(srv, timeout=0.8):
                    ip = entry.get("host")
                    if ip and ip != device.host and ip not in mdns_candidates:
                        mdns_candidates.append(ip)

            for cand_ip in mdns_candidates:
                if self.AndroidTVDiscovery.check_port(cand_ip, device.port, timeout=0.2):
                    match_ok, hw_id = self.AndroidTVDiscovery.verify_identity(
                        cand_ip,
                        device.port,
                        expected_fingerprint=expected_fp
                    )
                    if match_ok:
                        info = {"host": cand_ip, "port": device.port, "fingerprint": hw_id}
                        self.cache.set(device.id, info)
                        return True, DiscoveryMethod.MDNS.value, info

            # 2b. Zasilni izhod (fallback): pregled posredovanih kandidatov ali lokalnega podomrežja
            candidates = self._get_fallback_candidates(device, candidate_hosts)
            for cand_ip in candidates:
                if self.AndroidTVDiscovery.check_port(cand_ip, device.port, timeout=0.2):
                    match_ok, hw_id = self.AndroidTVDiscovery.verify_identity(
                        cand_ip,
                        device.port,
                        expected_fingerprint=expected_fp
                    )
                    if match_ok:
                        info = {"host": cand_ip, "port": device.port, "fingerprint": hw_id}
                        self.cache.set(device.id, info)
                        return True, DiscoveryMethod.ADB_PROBE.value, info

        elif device.type == DeviceType.AUDIO_SOUNDBAR:
            # 3a. Primarno: SSDP Multicast M-SEARCH
            discovered = self.SSDPDiscovery.multicast_msearch(timeout=1.0)
            for item in discovered:
                # Preveri, ali se ujema UDN ali ime naprave
                item_udn = item.get("udn", "")
                item_name = item.get("friendly_name", "").upper()
                dev_uuid = device.identity.device_uuid
                dev_name = device.name.upper()

                if (dev_uuid and dev_uuid in item_udn) or (dev_name and dev_name in item_name) or ("JBL" in dev_name and "JBL" in item_name):
                    self.cache.set(device.id, item)
                    return True, DiscoveryMethod.SSDP.value, item

            # 3b. Zasilni izhod (fallback): neposredno preiskovanje kandidatov
            candidates = self._get_fallback_candidates(device, candidate_hosts)
            for cand_ip in candidates:
                res = self.SSDPDiscovery.probe_host(cand_ip, device.port, timeout=0.3)
                if res:
                    self.cache.set(device.id, res)
                    return True, DiscoveryMethod.SSDP.value, res

        # 4. Fallback na obstoječi gostitelj
        return False, DiscoveryMethod.STATIC_FALLBACK.value, None

    @classmethod
    def _get_fallback_candidates(cls, device: Device, candidate_hosts: Optional[List[str]]) -> List[str]:
        if candidate_hosts is not None:
            return candidate_hosts
        base_parts = device.host.split(".")
        if len(base_parts) == 4:
            prefix = ".".join(base_parts[:3])
            return [f"{prefix}.{i}" for i in range(50, 155) if f"{prefix}.{i}" != device.host]
        return []

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
    MDNSDiscovery = MDNSDiscovery


_discovery_manager_instance: Optional[DynamicDiscoveryManager] = None


def get_discovery_manager() -> DynamicDiscoveryManager:
    global _discovery_manager_instance
    if _discovery_manager_instance is None:
        _discovery_manager_instance = DynamicDiscoveryManager()
    return _discovery_manager_instance
