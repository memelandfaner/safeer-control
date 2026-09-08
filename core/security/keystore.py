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
        elif os.environ.get("SAFEER_KEYSTORE_PATH"):
            self.storage_path = Path(os.environ["SAFEER_KEYSTORE_PATH"]).expanduser().resolve()
        else:
            base_dir = Path(os.environ.get("XDG_CONFIG_HOME", "~/.config")).expanduser()
            default_path = base_dir / "safeer-control" / "device_keys.json"
            fallback_path = Path(tempfile.gettempdir()) / "safeer-control" / "device_keys.json"

            # Preveri, ali je privzeta pot zapisljiva
            is_writable = False
            try:
                default_path.parent.mkdir(parents=True, exist_ok=True)
                test_f = default_path.parent / f".write_test_{os.getpid()}"
                test_f.touch()
                test_f.unlink()
                is_writable = True
            except OSError:
                is_writable = False

            if is_writable:
                self.storage_path = default_path
            else:
                self.storage_path = fallback_path

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
        try:
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
        except OSError:
            # V primeru read-only datotečnega sistema (peskovnik) uporabimo začasno mapo
            fallback_dir = Path(tempfile.gettempdir()) / "safeer-control"
            try:
                fallback_dir.mkdir(parents=True, exist_ok=True)
                with tempfile.NamedTemporaryFile("w", dir=fallback_dir, delete=False, encoding="utf-8") as tf:
                    json.dump(self._keys, tf, indent=2)
                    temp_name = tf.name
                os.chmod(temp_name, 0o600)
                fallback_target = fallback_dir / "device_keys.json"
                os.replace(temp_name, fallback_target)
                self.storage_path = fallback_target
            except Exception:
                pass

    @staticmethod
    def generate_random_key() -> str:
        """Generira kriptografsko varen 256-bitni ključ (64 hex znakov)."""
        return secrets.token_hex(MIN_KEY_LEN_BYTES)

    @staticmethod
    def compute_fingerprint(key: str) -> str:
        """Izračuna enosmerni SHA-256 prstni odtis ključa (prvih 12 hex znakov).
        Nikoli ne razkriva delov dejanskega HMAC ključa.
        """
        import hashlib
        return f"SHA256:{hashlib.sha256(key.encode('utf-8')).hexdigest()[:12]}"

    def get_fingerprint(self, device_id: str) -> Optional[str]:
        """Vrne zgolj enosmerni prstni odtis ključa naprave, nikoli skrivnega niza."""
        key = self.get_key(device_id)
        if not key:
            return None
        return self.compute_fingerprint(key)

    def get_key(self, device_id: str) -> Optional[str]:
        """Pridobi veljaven ključ za napravo (podpira staro obliko str ali novo dict)."""
        val = self._keys.get(device_id)
        key = val.get("key") if isinstance(val, dict) else val
        if key and len(key) >= MIN_KEY_LEN_BYTES * 2:  # 64 hex znakov = 256 bitov
            return key
        elif key and len(key) >= MIN_KEY_LEN_BYTES:   # raw 32 bajtov
            return key
        return None

    def get_tls_fingerprint(self, device_id: str) -> Optional[str]:
        """Pridobi pripet SHA-256 prstni odtis TLS certifikata naprave."""
        val = self._keys.get(device_id)
        if isinstance(val, dict):
            return val.get("tls_fingerprint")
        return None

    def set_tls_fingerprint(self, device_id: str, tls_fingerprint: str) -> None:
        """Pripne TLS prstni odtis za napravo za zaščito pred MITM."""
        val = self._keys.get(device_id)
        if isinstance(val, dict):
            val["tls_fingerprint"] = tls_fingerprint
        elif isinstance(val, str):
            self._keys[device_id] = {"key": val, "tls_fingerprint": tls_fingerprint}
        else:
            self._keys[device_id] = {"tls_fingerprint": tls_fingerprint}
        self._save()

    def set_key(self, device_id: str, key: str, tls_fingerprint: Optional[str] = None) -> None:
        """Centralno nastavi in validira ključ za napravo ter opcijsko shrani TLS prstni odtis."""
        if not key or len(key) < MIN_KEY_LEN_BYTES:
            raise ValueError(f"Ključ mora vsebovati vsaj {MIN_KEY_LEN_BYTES} znakov (256 bitov).")
        val = self._keys.get(device_id)
        existing_fp = val.get("tls_fingerprint") if isinstance(val, dict) else None
        fp_to_save = tls_fingerprint or existing_fp
        if fp_to_save:
            self._keys[device_id] = {"key": key, "tls_fingerprint": fp_to_save}
        else:
            self._keys[device_id] = {"key": key}
        self._save()

    def get_or_create_key(self, device_id: str, tls_fingerprint: Optional[str] = None) -> str:
        """Pridobi obstoječ ali generira nov unikatni ključ za napravo."""
        existing = self.get_key(device_id)
        if existing:
            if tls_fingerprint:
                self.set_tls_fingerprint(device_id, tls_fingerprint)
            return existing
        new_key = self.generate_random_key()
        self.set_key(device_id, new_key, tls_fingerprint=tls_fingerprint)
        return new_key

    def rotate_key(self, device_id: str, tls_fingerprint: Optional[str] = None) -> str:
        """Rotira ključ naprave: generira novega in povoziti starega."""
        new_key = self.generate_random_key()
        self.set_key(device_id, new_key, tls_fingerprint=tls_fingerprint)
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
