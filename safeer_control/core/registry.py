"""
Device Registry za Safeer Control.
Vzdržuje evidenco vseh znanih naprav, njihovo stanje in povezane ponudnike (DeviceProviders).
"""

from typing import Dict, List, Optional
from safeer_control.core.models import Device, DeviceType, DeviceStatus
from safeer_control.core.config import get_settings
from safeer_control.providers.base import BaseDeviceProvider
from safeer_control.providers.tv import AndroidTVProvider
from safeer_control.providers.audio import JBLAudioProvider


class DeviceRegistry:
    def __init__(self):
        self._devices: Dict[str, Device] = {}
        self._providers: Dict[str, BaseDeviceProvider] = {}
        self._initialize_from_settings()

    def _initialize_from_settings(self) -> None:
        """Inicializira privzete naprave iz konfiguracijskih nastavitev."""
        settings = get_settings()

        # 1. Android TV
        tv_dev = Device(
            id="living_room_tv",
            name=settings.tv_name,
            type=DeviceType.ANDROID_TV,
            host=settings.tv_host,
            port=settings.tv_port
        )
        self.register(tv_dev, AndroidTVProvider(tv_dev))

        # 2. JBL Audio Soundbar
        audio_dev = Device(
            id="living_room_audio",
            name=settings.audio_name,
            type=DeviceType.AUDIO_SOUNDBAR,
            host=settings.audio_host,
            port=settings.audio_port
        )
        self.register(audio_dev, JBLAudioProvider(audio_dev))

    def register(self, device: Device, provider: BaseDeviceProvider) -> None:
        """Registrira novo napravo in njenega ponudnika."""
        self._devices[device.id] = device
        self._providers[device.id] = provider

    def get_device(self, device_id: str) -> Optional[Device]:
        """Vrne napravo po identifikatorju."""
        return self._devices.get(device_id)

    def get_provider(self, device_id: str) -> Optional[BaseDeviceProvider]:
        """Vrne ponudnika za določeno napravo."""
        return self._providers.get(device_id)

    def list_devices(self) -> List[Device]:
        """Vrne seznam vseh registriranih naprav."""
        return list(self._devices.values())

    def refresh_status(self, device_id: str) -> Optional[DeviceStatus]:
        """Osveži in posodobi stanje posamezne naprave."""
        dev = self.get_device(device_id)
        prov = self.get_provider(device_id)
        if dev and prov:
            status = prov.get_status()
            dev.status = status
            return status
        return None

    def refresh_all(self) -> Dict[str, DeviceStatus]:
        """Osveži stanje vseh registriranih naprav."""
        results = {}
        for dev_id in self._devices:
            stat = self.refresh_status(dev_id)
            if stat:
                results[dev_id] = stat
        return results


_registry_instance: Optional[DeviceRegistry] = None


def get_registry() -> DeviceRegistry:
    """Vrne enotno instanco registra (Singleton)."""
    global _registry_instance
    if _registry_instance is None:
        _registry_instance = DeviceRegistry()
    return _registry_instance
