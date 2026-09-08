"""
Shizuku / Android Privileged Execution Runner za Safeer Companion (V0.6.1).
Izvaja operacije prek rish vmesnika ali neposredne Android shell lupine na napravi.
Privzeto deluje fail-closed (shizuku_available=False, permission_granted=False),
dokler dinamično preverjanje ne dokaže prisotnosti Shizuku in dodeljenih pravic.
"""

import os
import shutil
import subprocess
from typing import Dict, Any, Tuple, Optional, Callable
from companion.gate import CompanionGate
from companion.protocol import Capability


class ShizukuRunner:
    """
    Upravitelj lokalnih Shizuku privilegijev na Android napravi.
    Vsi klici morajo biti predhodno avtorizirani skozi CompanionGate (Gate #2).
    """

    def __init__(
        self,
        rish_path: Optional[str] = None,
        mock_mode: bool = False,
        executor: Optional[Callable[[list[str]], Tuple[int, str, str]]] = None,
    ):
        self.mock_mode = mock_mode
        self._custom_executor = executor
        self._rish_path: Optional[str] = rish_path
        self._execution_mode: str = "none"  # "rish" | "direct_shell" | "mock" | "none"
        self._status_reason: str = "Unverified"

        # Privzeto fail-closed
        self._shizuku_available: bool = False
        self._permission_granted: bool = False

        if self.mock_mode:
            self._shizuku_available = True
            self._permission_granted = True
            self._execution_mode = "mock"
            self._status_reason = "Mock mode enabled"
        else:
            self.probe_shizuku()

    def probe_shizuku(self) -> Tuple[bool, bool, str]:
        """
        Dinamično preveri, ali je Shizuku storitev na voljo in ali ima proces dodeljene pravice.
        Vrne (shizuku_available, permission_granted, reason).
        """
        if self.mock_mode:
            return True, True, "Mock mode enabled"

        # 1. Poišči rish izvršljivo datoteko
        candidate_paths = []
        if self._rish_path:
            candidate_paths.append(self._rish_path)
        env_rish = os.environ.get("RISH_PATH")
        if env_rish:
            candidate_paths.append(env_rish)
        which_rish = shutil.which("rish")
        if which_rish:
            candidate_paths.append(which_rish)
        candidate_paths.extend([
            "/system/bin/rish",
            "/data/data/com.termux/files/usr/bin/rish",
            "/data/local/tmp/rish",
            "./rish",
        ])

        resolved_rish: Optional[str] = None
        for p in candidate_paths:
            if self._custom_executor:
                resolved_rish = p
                break
            if os.path.isfile(p) and os.access(p, os.X_OK):
                resolved_rish = os.path.abspath(p)
                break

        if resolved_rish:
            self._rish_path = resolved_rish
            # Testiraj izvajanje prek rish
            try:
                if self._custom_executor:
                    rc, out, err = self._custom_executor([resolved_rish, "-c", "id"])
                else:
                    proc = subprocess.run(
                        [resolved_rish, "-c", "id"],
                        capture_output=True,
                        text=True,
                        timeout=4,
                    )
                    rc, out, err = proc.returncode, proc.stdout, proc.stderr

                if rc == 0 and ("uid=2000" in out or "uid=0" in out or "gid=2000" in out):
                    self._shizuku_available = True
                    self._permission_granted = True
                    self._execution_mode = "rish"
                    self._status_reason = f"Shizuku aktiven prek rish ({resolved_rish})"
                    return True, True, self._status_reason
                elif "permission" in (out + err).lower() or "denied" in (out + err).lower() or rc == 13:
                    self._shizuku_available = True
                    self._permission_granted = False
                    self._execution_mode = "none"
                    self._status_reason = f"Shizuku zaznan, vendar dovoljenje ni dodeljeno: {err or out}".strip()
                    return True, False, self._status_reason
                else:
                    self._shizuku_available = False
                    self._permission_granted = False
                    self._execution_mode = "none"
                    self._status_reason = f"Shizuku ni odziven ali rish ni uspel (rc={rc}): {err or out}".strip()
                    return False, False, self._status_reason
            except Exception as e:
                self._shizuku_available = False
                self._permission_granted = False
                self._execution_mode = "none"
                self._status_reason = f"Napaka pri preverjanju rish: {e}"
                return False, False, self._status_reason

        # 2. Če rish ni na voljo, preveri, ali proces že teče kot Android shell (UID 2000) ali root (UID 0)
        if hasattr(os, "getuid") and os.path.exists("/system/bin/sh"):
            try:
                uid = os.getuid()
                if uid in (2000, 0):
                    self._shizuku_available = True
                    self._permission_granted = True
                    self._execution_mode = "direct_shell"
                    self._status_reason = f"Neposredni Android shell privilegiji (UID {uid})"
                    return True, True, self._status_reason
            except Exception:
                pass

        # 3. Fail-closed: okolje ni Android z ustreznimi privilegiji
        self._shizuku_available = False
        self._permission_granted = False
        self._execution_mode = "none"
        self._status_reason = "Shizuku/rish ni najden in okolje nima Android privilegijev (Fail-Closed)"
        return False, False, self._status_reason

    def _run_privileged(self, android_cmd: list[str]) -> Tuple[int, str, str]:
        """
        Izvede privilegiran ukaz prek preverjenega rish ali direct shell kanala.
        Parametri so predhodno validirani s strani Gate #2.
        """
        if self._custom_executor:
            return self._custom_executor(android_cmd)

        if self._execution_mode == "rish" and self._rish_path:
            full_cmd = [self._rish_path, "-c", " ".join(android_cmd)]
        elif self._execution_mode == "direct_shell":
            full_cmd = android_cmd
        elif self.mock_mode:
            # Privzeti mock odziv za teste brez custom executorja
            if android_cmd[:2] == ["settings", "get"]:
                return 0, "1\n", ""
            return 0, "success\n", ""
        else:
            return 1, "", f"Ni aktivnega privilegiranega načina izvajanja: {self._status_reason}"

        try:
            res = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                timeout=5,
            )
            return res.returncode, res.stdout, res.stderr
        except subprocess.TimeoutExpired:
            return 124, "", "Časovna omejitev izvedbe (timeout 5s)"
        except Exception as e:
            return 1, "", f"Sistemska napaka pri zagonu: {e}"

    def get_health(self) -> Dict[str, Any]:
        """Vrne status delovanja Companiona in veljavnosti Shizuku privilegijev."""
        # Ob health pregledu po potrebi ponovno osveži stanje, če še ni potrjeno
        if not self._shizuku_available or not self._permission_granted:
            if not self.mock_mode:
                self.probe_shizuku()

        return {
            "status": "ok" if (self._shizuku_available and self._permission_granted) else "degraded",
            "protocol_version": "1.0",
            "companion_running": True,
            "shizuku_available": self._shizuku_available,
            "shizuku_permission_granted": self._permission_granted,
            "execution_mode": self._execution_mode,
            "details": self._status_reason,
        }

    def execute_capability(
        self,
        capability: Capability,
        params: Dict[str, Any]
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """
        Izvede zahtevano zmožnost, potem ko jo potrdi CompanionGate.
        """
        # 1. Preveritev skozi CompanionGate (Gate #2)
        gate_ok, gate_reason = CompanionGate.require(capability, params)
        if not gate_ok:
            return False, f"Zavrnjeno s strani Gate #2: {gate_reason}", None

        # 2. Preveritev Shizuku privilegijev (Fail-Closed)
        if not self._shizuku_available or not self._permission_granted:
            if not self.mock_mode:
                self.probe_shizuku()
            if not self._shizuku_available or not self._permission_granted:
                return False, f"Shizuku storitev na napravi ni aktivirana ali nima dodeljenih dovoljenj ({self._status_reason}).", None

        # 3. Izvedba posamezne zmožnosti
        if capability == Capability.SETTINGS_READ:
            ns = str(params["namespace"]).strip().lower()
            key = str(params["key"]).strip()

            cmd = ["settings", "get", ns, key]
            rc, stdout, stderr = self._run_privileged(cmd)

            if rc != 0:
                return False, f"Napaka pri branju nastavitve '{ns}.{key}': {stderr.strip() or stdout.strip()}", None

            raw_val = stdout.strip()
            # Android 'settings get' vrne 'null' za neobstoječo/privzeto vrednost
            val = None if raw_val in ("null", "") else raw_val
            return True, f"Nastavitev '{ns}.{key}' uspešno prebrana.", {
                "namespace": ns,
                "key": key,
                "value": val,
            }

        elif capability == Capability.APP_FORCE_STOP:
            pkg = str(params["package"]).strip()

            cmd = ["am", "force-stop", pkg]
            rc, stdout, stderr = self._run_privileged(cmd)

            if rc != 0:
                return False, f"Napaka pri zaustavitvi aplikacije '{pkg}': {stderr.strip() or stdout.strip()}", None

            return True, f"Aplikacija '{pkg}' uspešno zaustavljena (Shizuku).", {"package": pkg}

        elif capability == Capability.APP_CACHE_MAINTENANCE:
            pkg = str(params["package"]).strip()

            # Ciljno čiščenje zunanjega predpomnilnika natanko za ta paket brez globalnih stranskih učinkov
            cmd_rm = ["rm", "-rf", f"/sdcard/Android/data/{pkg}/cache/*"]
            rc_rm, out_rm, err_rm = self._run_privileged(cmd_rm)

            if rc_rm != 0:
                err_msg = err_rm.strip() or out_rm.strip()
                return False, f"Napaka pri čiščenju predpomnilnika za '{pkg}': {err_msg}", None

            return True, f"Predpomnilnik aplikacije '{pkg}' uspešno očiščen (Shizuku).", {
                "package": pkg,
                "cache_cleared": True,
            }


        return False, f"Neznana zmožnost: {capability}", None
