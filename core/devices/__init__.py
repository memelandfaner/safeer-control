"""
Safeer Control — Devices Core Module.
"""

from core.devices.models import Device, DeviceType, DeviceStatus

def get_registry():
    from core.devices.registry import get_registry as _gr
    return _gr()

def __getattr__(name: str):
    if name == "DeviceRegistry":
        from core.devices.registry import DeviceRegistry
        return DeviceRegistry
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = ["Device", "DeviceType", "DeviceStatus", "DeviceRegistry", "get_registry"]

