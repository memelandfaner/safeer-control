"""
Device KeyStore za Safeer Control V0.6.2.
Upravlja unikatne 256-bitne kriptografske ključe naprav z varnim shranjevanjem
izven repozitorija z datotečnimi pravicami 0600 (Zero Token Policy).
"""

import json
import os
import secrets
import tempfile
from pathlib import Path
from typing import Dict, List, Optional


MIN_KEY_LEN_BYTES = 32  # 256 bitov


class DeviceKeyStore:
    """
    Varna lokalna shramba seznanjenih ključev naprav.
    Vsaka naprava (npr. telefon, TV) dobi svoj unikatni kriptografski ključ.
    """

    def __init__(self, storage_path: Optional[str] = None):
        if storage_path:
            self.storage_path = Path(storage_path).expanduser().resolve()
        else:
            base_dir = Path(os.environ.get("XDG_CONFIG_HOME", "~/.config")).expanduser()
            self.storage_path = base_dir / "safeer-control" / "device_keys.json"

        self._keys: Dict[str, str] = {}
        self._load()

    def _load(self) -> None:
        """Naloži ključe iz varovane datoteke."""
        if not self.storage_path.exists():
            return

        try:
            with open(self.storage_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    self._keys = {str(k): str(v) for k, v in data.items()}
        except Exception:
            self._keys = {}

    def _save(self) -> None:
        """Atomarno shrani ključe z varnimi pravicami 0600."""
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.storage_path.parent, 0o700)
        except OSError:
            pass

        tmp_dir = self.storage_path.parent
        with tempfile.NamedTemporaryFile("w", dir=tmp_dir, delete=False, encoding="utf-8") as tf:
            json.dump(self._keys, tf, indent=2)
            temp_name = tf.name

        os.chmod(temp_name, 0o600)
        os.replace(temp_name, self.storage_path)

    @staticmethod
    def generate_random_key() -> str:
        """Generira kriptografsko varen 256-bitni ključ (64 hex znakov)."""
        return secrets.token_hex(MIN_KEY_LEN_BYTES)

    def get_key(self, device_id: str) -> Optional[str]:
        """Pridobi veljaven ključ za napravo."""
        key = self._keys.get(device_id)
        if key and len(key) >= MIN_KEY_LEN_BYTES * 2:  # 64 hex znakov = 256 bitov
            return key
        elif key and len(key) >= MIN_KEY_LEN_BYTES:   # raw 32 bajtov
            return key
        return None

    def get_or_create_key(self, device_id: str) -> str:
        """Pridobi obstoječ ali generira nov unikatni ključ za napravo."""
        existing = self.get_key(device_id)
        if existing:
            return existing
        new_key = self.generate_random_key()
        self._keys[device_id] = new_key
        self._save()
        return new_key

    def rotate_key(self, device_id: str) -> str:
        """Rotira ključ naprave: generira novega in povoziti starega."""
        new_key = self.generate_random_key()
        self._keys[device_id] = new_key
        self._save()
        return new_key

    def revoke_key(self, device_id: str) -> bool:
        """Prekliče ključ naprave in jo odstrani iz shrambe."""
        if device_id in self._keys:
            del self._keys[device_id]
            self._save()
            return True
        return False

    def list_devices(self) -> List[str]:
        """Vrne seznam ID-jev vseh seznanjenih naprav."""
        return list(self._keys.keys())


_default_keystore: Optional[DeviceKeyStore] = None


def get_keystore() -> DeviceKeyStore:
    """Singleton dostop do globalne shrambe ključev naprav."""
    global _default_keystore
    if _default_keystore is None:
        _default_keystore = DeviceKeyStore()
    return _default_keystore
