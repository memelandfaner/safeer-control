"""
Device Discovery modul za samodejno odkrivanje naprav v lokalnem omrežju.
Podpira mDNS/SSDP in omrežno skeniranje vrat (ADB 5555, UPnP 49152, Cast 8009).
"""

import socket
from typing import List, Dict, Any
from core.devices.models import Device, DeviceType


class DeviceDiscovery:
    """
    Orodje za odkrivanje naprav v lokalnem omrežju.
    """

    KNOWN_PORTS = {
        5555: ("Android TV (ADB)", DeviceType.ANDROID_TV),
        49152: ("JBL / UPnP Soundbar", DeviceType.AUDIO_SOUNDBAR),
        8009: ("Google Cast / Chromecast", DeviceType.CAST),
    }

    @classmethod
    def probe_host(cls, host: str, timeout: float = 0.5) -> List[Dict[str, Any]]:
        """Preveri odprta vrata na določenem IP naslovu."""
        found = []
        for port, (desc, dev_type) in cls.KNOWN_PORTS.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            try:
                result = sock.connect_ex((host, port))
                if result == 0:
                    found.append({
                        "host": host,
                        "port": port,
                        "type": dev_type,
                        "description": desc
                    })
            except Exception:
                pass
            finally:
                sock.close()
        return found
