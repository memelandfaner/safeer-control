"""
Testi za Safeer Kriptografski Trust Model in Device Pairing (Handshake).
"""

from core.pairing.handshake import DevicePairing
from core.devices.models import Device, DeviceType, DeviceIdentity


def test_pin_generation_and_verification():
    pairing = DevicePairing()
    pin = pairing.generate_pairing_pin("tv_test")
    assert len(pin) == 6
    assert pin.isdigit()

    # Napačen PIN
    assert not pairing.verify_pin("tv_test", "000000")

    # Veljaven PIN
    assert pairing.verify_pin("tv_test", pin)

    # PIN je enkraten (one-time)
    assert not pairing.verify_pin("tv_test", pin)


def test_cryptographic_device_identity():
    pairing = DevicePairing()
    identity, secret = pairing.create_paired_identity("living_room_tv")

    assert identity.trusted is True
    assert identity.device_uuid is not None
    assert identity.auth_token_hash is not None

    # Preveri veljaven secret
    assert pairing.verify_device_token(identity, secret) is True

    # Napačen secret zavrnjen
    assert pairing.verify_device_token(identity, "attacker-secret-xyz") is False
    assert pairing.verify_device_token(identity, "") is False
