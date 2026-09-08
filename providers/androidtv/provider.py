"""
Android TV Provider za Safeer Control.
Nadzor televizorja preko ADB in integracija s Safeer Browserjem.
"""

import time
import subprocess
from typing import Any, Dict
from core.devices.models import Device, DeviceStatus
from core.actions.models import ActionResult
from providers.base import BaseDeviceProvider


class AndroidTVProvider(BaseDeviceProvider):
    APP_LABELS = {
        "com.example.safeerbrowser": "Safeer Browser",
        "org.droidtv.playtv": "TV Predvajalnik (Live TV / HDMI)",
        "org.smarttube.stable": "SmartTube (YouTube)",
        "com.streamnexus.tv": "StreamTV",
        "com.google.android.tvlauncher": "Domači zaslon (Home)",
        "com.google.android.youtube.tv": "YouTube TV",
        "org.droidtv.nettvbrowser": "Sistemski Brskalnik",
    }

    def __init__(self, device: Device):
        super().__init__(device)
        self.target = f"{self.device.host}:{self.device.port}"

    def connect(self) -> bool:
        try:
            res = subprocess.run(
                ["adb", "connect", self.target],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=3.0
            )
            return "connected" in res.stdout.lower() or "already connected" in res.stdout.lower()
        except Exception:
            return False

    def disconnect(self) -> None:
        try:
            subprocess.run(["adb", "disconnect", self.target], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2.0)
        except Exception:
            pass

    def check_authorization(self) -> str:
        """Preveri stanje avtorizacije ADB povezave (device, unauthorized, offline)."""
        try:
            res = subprocess.run(["adb", "devices"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2.0)
            for line in res.stdout.splitlines():
                if self.target in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[1]
            return "disconnected"
        except Exception:
            return "error"

    def _adb(self, args: list[str], timeout: float = 5.0) -> str:
        try:
            subprocess.run(["adb", "connect", self.target], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2.0)
            cmd = ["adb", "-s", self.target] + args
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
            return res.stdout.strip()
        except Exception as e:
            return f"ERROR: {e}"

    def get_status(self) -> DeviceStatus:
        lat = self.ping(1.0)
        if lat < 0:
            return DeviceStatus(online=False, latency_ms=-1.0, power_on=False, active_app="Brez povezave")

        # 1. Preveri stanje zaslona / budnosti
        power_out = self._adb(["shell", "dumpsys", "power"])
        is_awake = ("mWakefulness=Awake" in power_out) or ("Display Power: state=ON" in power_out)

        # 2. Preveri aktivno osprednjo aplikacijo
        active_app = "Domači zaslon" if is_awake else "V mirovanju"
        if is_awake:
            win_out = self._adb(["shell", "dumpsys", "window"])
            for line in win_out.splitlines():
                if "mCurrentFocus" in line or "mFocusedApp" in line:
                    matched = False
                    for pkg, label in self.APP_LABELS.items():
                        if pkg in line:
                            active_app = label
                            matched = True
                            break
                    if not matched and "/" in line:
                        try:
                            pkg_part = line.split("{")[1].split("/")[0].split()[-1]
                            active_app = pkg_part
                        except Exception:
                            pass
                    break

        auth_state = self.check_authorization()

        return DeviceStatus(
            online=True,
            latency_ms=lat,
            power_on=is_awake,
            active_app=active_app,
            extra={
                "adb_connected": auth_state == "device",
                "adb_status": auth_state
            }
        )

    def execute_action(self, action: str, params: Dict[str, Any]) -> ActionResult:
        t0 = time.time()
        action = action.lower().strip()

        try:
            if action == "status":
                stat = self.get_status()
                return ActionResult(
                    success=stat.online,
                    device_id=self.device.id,
                    action=action,
                    message="Status osvežen",
                    data=stat.model_dump(),
                    elapsed_ms=(time.time() - t0) * 1000
                )

            elif action == "pair":
                ok = self.connect()
                auth = self.check_authorization()
                msg = f"Seznanjeno z Android TV ({auth})" if auth == "device" else f"ADB Stanje: {auth}"
                return ActionResult(success=(auth == "device"), device_id=self.device.id, action=action, message=msg, data={"adb_status": auth})

            elif action in ("back", "nazaj"):
                out = self._adb(["shell", "input", "keyevent", "4"])
                return ActionResult(success=True, device_id=self.device.id, action=action, message="TV Nazaj (Back)", data=out)

            elif action in ("home", "domov"):
                out = self._adb(["shell", "input", "keyevent", "3"])
                return ActionResult(success=True, device_id=self.device.id, action=action, message="TV Domov (Home)", data=out)

            elif action in ("power", "power_toggle"):
                out = self._adb(["shell", "input", "keyevent", "26"])
                return ActionResult(success=True, device_id=self.device.id, action=action, message="TV Power Toggle", data=out)

            elif action in ("wake", "power_on"):
                out = self._adb(["shell", "input", "keyevent", "224"])
                return ActionResult(success=True, device_id=self.device.id, action=action, message="TV Wakeup", data=out)

            elif action in ("sleep", "power_off"):
                out = self._adb(["shell", "input", "keyevent", "223"])
                return ActionResult(success=True, device_id=self.device.id, action=action, message="TV Sleep", data=out)

            elif action == "key":
                keycode = params.get("keycode", 3)
                out = self._adb(["shell", "input", "keyevent", str(keycode)])
                return ActionResult(success=True, device_id=self.device.id, action=action, message=f"Tipka {keycode}", data=out)

            elif action == "open_url":
                url = params.get("url", "")
                out = self._adb(["shell", "am", "start", "-n", "com.example.safeerbrowser/.MainActivity", "-d", str(url)])
                return ActionResult(success=True, device_id=self.device.id, action=action, message=f"Odprt URL: {url}", data=out)

            elif action == "open_browser":
                out = self._adb(["shell", "am", "start", "-n", "com.example.safeerbrowser/.MainActivity"])
                return ActionResult(success=True, device_id=self.device.id, action=action, message="Safeer Browser zagnan", data=out)

            elif action == "open_smarttube":
                query = params.get("query", "")
                if query:
                    escaped = query.replace(" ", "%s").replace("'", "\\'")
                    out = self._adb(["shell", "am", "start", "-a", "android.intent.action.SEARCH", "-n", "org.smarttube.stable/com.liskovsoft.leanbackassistant.search.SearchableActivity", "--es", "query", escaped])
                else:
                    out = self._adb(["shell", "am", "start", "-n", "org.smarttube.stable/com.liskovsoft.smartyoutubetv2.tv.ui.main.SplashActivity"])
                return ActionResult(success=True, device_id=self.device.id, action=action, message="SmartTube zagnan", data=out)

            elif action == "open_xplore_tv":
                out = self._adb(["shell", "am", "start", "-n", "com.example.safeerbrowser/.MainActivity", "-d", "https://www.xploretv.si/livetv"])
                channel = params.get("channel")
                if channel:
                    time.sleep(0.5)
                    self._adb(["shell", "am", "broadcast", "-a", "com.example.safeerbrowser.ACTION_CHANNEL_TUNE", "--ei", "channel", str(channel)])
                return ActionResult(success=True, device_id=self.device.id, action=action, message="Xplore TV zagnan", data=out)

            elif action == "open_streamtv":
                query = params.get("query", "")
                if query:
                    out = self._adb(["shell", "am", "start", "-n", "com.streamnexus.tv/.MainActivity", "--es", "query", query, "--ez", "autoplay", "true"])
                else:
                    out = self._adb(["shell", "am", "start", "-n", "com.streamnexus.tv/.MainActivity"])
                return ActionResult(success=True, device_id=self.device.id, action=action, message="StreamTV zagnan", data=out)

            elif action == "launch_app":
                pkg = params.get("package", "")
                out = self._adb(["shell", "monkey", "-p", pkg, "-c", "android.intent.category.LAUNCHER", "1"])
                return ActionResult(success=True, device_id=self.device.id, action=action, message=f"Aplikacija {pkg} zagnana", data=out)

            elif action == "tune_channel":
                ch = params.get("channel", 1)
                out = self._adb(["shell", "am", "broadcast", "-a", "com.example.safeerbrowser.ACTION_CHANNEL_TUNE", "--ei", "channel", str(ch)])
                return ActionResult(success=True, device_id=self.device.id, action=action, message=f"Preklop na kanal {ch}", data=out)

            elif action == "play_pause":
                self._adb(["shell", "am", "broadcast", "-a", "com.example.safeerbrowser.ACTION_PLAY_PAUSE"])
                out = self._adb(["shell", "input", "keyevent", "85"])
                return ActionResult(success=True, device_id=self.device.id, action=action, message="Predvajanje / Pavza preklopljeno", data=out)

            elif action == "seek":
                secs = params.get("seconds", 10)
                out = self._adb(["shell", "am", "broadcast", "-a", "com.example.safeerbrowser.ACTION_SEEK", "--ei", "seconds", str(secs)])
                return ActionResult(success=True, device_id=self.device.id, action=action, message=f"Previjanje {secs} s", data=out)

            elif action == "search":
                q = params.get("query", "")
                engine = params.get("engine", "google")
                out = self._adb(["shell", "am", "broadcast", "-a", "com.example.safeerbrowser.ACTION_SEARCH", "--es", "query", q, "--es", "engine", engine])
                return ActionResult(success=True, device_id=self.device.id, action=action, message=f"Iskanje '{q}' ({engine})", data=out)

            elif action == "switch_input":
                target_in = params.get("input", "pc").lower()
                if target_in in ("pc", "hdmi1"):
                    out = self._adb(["shell", "am", "start", "-n", "org.droidtv.playtv/.PlayTvActivity", "-a", "android.intent.action.VIEW", "-d", "content://android.media.tv/passthrough/com.mediatek.tvinput/.hdmi.HDMIInputService/HW5"])
                elif target_in in ("ps5", "hdmi2"):
                    out = self._adb(["shell", "am", "start", "-n", "org.droidtv.playtv/.PlayTvActivity", "-a", "android.intent.action.VIEW", "-d", "content://android.media.tv/passthrough/com.mediatek.tvinput/.hdmi.HDMIInputService/HW6"])
                else:
                    return ActionResult(success=False, device_id=self.device.id, action=action, message=f"Neznan vhod {target_in}")
                return ActionResult(success=True, device_id=self.device.id, action=action, message=f"Preklopljeno na {target_in.upper()}", data=out)

            elif action == "type_text":
                text = params.get("text", "")
                escaped = text.replace(" ", "%s").replace("'", "\\'")
                out = self._adb(["shell", "input", "text", escaped])
                return ActionResult(success=True, device_id=self.device.id, action=action, message="Besedilo vpisano", data=out)

            elif action == "screenshot":
                try:
                    res = subprocess.run(
                        ["adb", "-s", self.target, "exec-out", "screencap", "-p"],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=5.0
                    )
                    if res.returncode == 0 and len(res.stdout) > 1000:
                        return ActionResult(success=True, device_id=self.device.id, action=action, message="Posnetek zajet", data={"bytes_len": len(res.stdout)})
                    return ActionResult(success=False, device_id=self.device.id, action=action, message="Zajem ni uspel")
                except Exception as e:
                    return ActionResult(success=False, device_id=self.device.id, action=action, message=f"Napaka pri zajemu: {e}")

            elif action == "clear_cache_and_restart":
                self._adb(["shell", "am", "force-stop", "com.example.safeerbrowser"])
                time.sleep(0.3)
                out = self._adb(["shell", "am", "start", "-n", "com.example.safeerbrowser/.MainActivity"])
                return ActionResult(success=True, device_id=self.device.id, action=action, message="Brskalnik ponovno zagnan", data=out)

            return ActionResult(
                success=False,
                device_id=self.device.id,
                action=action,
                message=f"Neznano dejanje: {action}",
                elapsed_ms=(time.time() - t0) * 1000
            )
        except Exception as e:
            return ActionResult(
                success=False,
                device_id=self.device.id,
                action=action,
                message=f"Napaka pri izvajanju: {e}",
                elapsed_ms=(time.time() - t0) * 1000
            )
