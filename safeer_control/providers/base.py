"""
Abstraktni osnovni razred za vse ponudnike naprav (DeviceProviders).
"""

import time
import subprocess
from abc import ABC, abstractmethod
from typing import Any, Dict
from safeer_control.core.models import Device, DeviceStatus, ActionResult


class BaseDeviceProvider(ABC):
    def __init__(self, device: Device):
        self.device = device

    @abstractmethod
    def connect(self) -> bool:
        """Vzpostavi povezavo z napravo."""
        pass

    @abstractmethod
    def disconnect(self) -> None:
        """Prekine povezavo z napravo."""
        pass

    @abstractmethod
    def get_status(self) -> DeviceStatus:
        """Vrne trenutno stanje naprave."""
        pass

    @abstractmethod
    def execute_action(self, action: str, params: Dict[str, Any]) -> ActionResult:
        """Izvede varno preverjeno dejanje na napravi."""
        pass

    def ping(self, timeout_sec: float = 1.0) -> float:
        """Izmeri omrežno latenco do naprave z ukazom ping v ms. Vrne -1.0 če ni odziva."""
        try:
            res = subprocess.run(
                ["ping", "-c", "1", "-W", str(int(timeout_sec)), self.device.host],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout_sec + 0.5
            )
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    if "time=" in line:
                        return float(line.split("time=")[1].split()[0])
            return -1.0
        except Exception:
            return -1.0
