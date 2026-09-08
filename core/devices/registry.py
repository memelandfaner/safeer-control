"""
Device Registry za Safeer Control V0.4 (Dynamic Device Discovery).
Uveljavlja ločitev device_id != IP address in samodejno re-lociranje ob DHCP spremembah.
"""

from typing import Dict, List, Optional
from core.devices.models import Device, DeviceType, DeviceStatus, DeviceIdentity
from core.config import get_settings
from core.devices.discovery import get_discovery_manager
from providers.base import BaseDeviceProvider
from providers.androidtv import AndroidTVProvider
from providers.upnp import UPnPProvider
from providers.android import AndroidProvider


class DeviceRegistry:
    def __init__(self):
        self._devices: Dict[str, Device] = {}
        self._providers: Dict[str, BaseDeviceProvider] = {}
        self.discovery_manager = get_discovery_manager()
        self._initialize_from_settings()

    def _initialize_from_settings(self) -> None:
        settings = get_settings()

        # 1. Android TV
        tv_dev = Device(
            id="living_room_tv",
            name=settings.tv_name,
            type=DeviceType.ANDROID_TV,
            host=settings.tv_host,
            port=settings.tv_port,
            identity=DeviceIdentity(device_uuid="tv-living-room-guid", trusted=True)
        )
        self.register(tv_dev, AndroidTVProvider(tv_dev))

        # 2. JBL Audio Soundbar
        audio_dev = Device(
            id="living_room_audio",
            name=settings.audio_name,
            type=DeviceType.AUDIO_SOUNDBAR,
            host=settings.audio_host,
            port=settings.audio_port,
            identity=DeviceIdentity(device_uuid="audio-jbl-300-guid", trusted=True)
        )
        self.register(audio_dev, UPnPProvider(audio_dev))

        # 3. Android Telefon (Galaxy S25)
        phone_dev = Device(
            id="phone_galaxy",
            name="Galaxy S25 (Ta naprava)",
            type=DeviceType.ANDROID_PHONE,
            host="127.0.0.1",
            port=0,
            identity=DeviceIdentity(device_uuid="phone-galaxy-s25-guid", trusted=True)
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

    def resolve_locator(self, device_id: str, candidate_hosts: Optional[List[str]] = None) -> bool:
        """
        Poskusi ponovno najti napravo v omrežju in posodobiti njen omrežni lokator,
        če je DHCP spremenil njen IP naslov.
        """
        dev = self.get_device(device_id)
        prov = self.get_provider(device_id)
        if not dev or not prov:
            return False

        ok, method, details = self.discovery_manager.resolve_device(dev, candidate_hosts=candidate_hosts)
        if ok and details:
            new_host = details["host"]
            new_port = details.get("port", dev.port)
            dev.update_locator(new_host=new_host, new_port=new_port, method=method)

            # Posodobi cilj v Providerju
            if hasattr(prov, "update_target"):
                ctrl_url = details.get("control_url")
                import inspect
                sig = inspect.signature(prov.update_target)
                if "control_url" in sig.parameters:
                    prov.update_target(new_host, new_port, control_url=ctrl_url)
                else:
                    prov.update_target(new_host, new_port)

            return True

        return False

    def refresh_status(self, device_id: str, auto_discover: bool = True) -> Optional[DeviceStatus]:
        dev = self.get_device(device_id)
        prov = self.get_provider(device_id)
        if not dev or not prov:
            return None

        status = prov.get_status()

        # Če naprava ni dosegljiva, poskusi dinamično ponovno odkrivanje (DHCP resilience)
        if (not status.online or status.latency_ms < 0) and auto_discover:
            re_located = self.resolve_locator(device_id)
            if re_located:
                status = prov.get_status()

        dev.status = status
        return status

    def refresh_all(self, auto_discover: bool = True) -> Dict[str, DeviceStatus]:
        results = {}
        for dev_id in self._devices:
            stat = self.refresh_status(dev_id, auto_discover=auto_discover)
            if stat:
                results[dev_id] = stat
        return results


_registry_instance: Optional[DeviceRegistry] = None


def get_registry() -> DeviceRegistry:
    global _registry_instance
    if _registry_instance is None:
        _registry_instance = DeviceRegistry()
    return _registry_instance
