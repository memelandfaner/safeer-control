"""
Device Registry za Safeer Control.
Evidenca registriranih naprav in povezava z DeviceProviderji.
"""

from typing import Dict, List, Optional
from core.devices.models import Device, DeviceType, DeviceStatus
from core.config import get_settings
from providers.base import BaseDeviceProvider
from providers.androidtv import AndroidTVProvider
from providers.upnp import UPnPProvider
from providers.android import AndroidProvider


class DeviceRegistry:
    def __init__(self):
        self._devices: Dict[str, Device] = {}
        self._providers: Dict[str, BaseDeviceProvider] = {}
        self._initialize_from_settings()

    def _initialize_from_settings(self) -> None:
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
        self.register(audio_dev, UPnPProvider(audio_dev))

        # 3. Android Telefon (Galaxy S25)
        phone_dev = Device(
            id="phone_galaxy",
            name="Galaxy S25 (Ta naprava)",
            type=DeviceType.ANDROID_PHONE,
            host="127.0.0.1",
            port=0
        )
        self.register(phone_dev, AndroidProvider(phone_dev))

    def register(self, device: Device, provider: BaseDeviceProvider) -> None:
        self._devices[device.id] = device
        self._providers[device.id] = provider

    def get_device(self, device_id: str) -> Optional[Device]:
        return self._devices.get(device_id)

    def get_provider(self, device_id: str) -> Optional[BaseDeviceProvider]:
        return self._providers.get(device_id)

    def list_devices(self) -> List[Device]:
        return list(self._devices.values())

    def refresh_status(self, device_id: str) -> Optional[DeviceStatus]:
        dev = self.get_device(device_id)
        prov = self.get_provider(device_id)
        if dev and prov:
            status = prov.get_status()
            dev.status = status
            return status
        return None

    def refresh_all(self) -> Dict[str, DeviceStatus]:
        results = {}
        for dev_id in self._devices:
            stat = self.refresh_status(dev_id)
            if stat:
                results[dev_id] = stat
        return results


_registry_instance: Optional[DeviceRegistry] = None


def get_registry() -> DeviceRegistry:
    global _registry_instance
    if _registry_instance is None:
        _registry_instance = DeviceRegistry()
    return _registry_instance
