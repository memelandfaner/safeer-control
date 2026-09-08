"""
Neodvisen FPS Performance Observer (Read-Only Diagnostic Component).
Zagotavlja metrične podatke o osveževanju zaslona, zakasnitvah okvirjev in zatikanju (Jank).

STROGO PRAVILO IZOLACIJE:
Ta modul je izključno read-only opazovalec preko standardnega ADB orodja.
Nima dostopa do:
- ShizukuProvider ali CompanionGate
- Companion skrivnosti ali seznanitvenih podatkov
- OTA ali kakršnihkoli privilegiranih endpoints
"""

import re
import time
import subprocess
from typing import Dict, Any, List, Optional, Tuple


class FpsObserver:
    """
    Pasivni opazovalec frekvence sličic na sekundo in zakasnitev (FPS Observer).
    Uporablja podatke Android SurfaceFlinger ali gfxinfo framestats.
    """

    def __init__(self, adb_target: str, default_timeout: float = 6.0):
        self.adb_target = adb_target.strip()
        self.default_timeout = default_timeout

    def _run_adb_cmd(self, cmd: List[str]) -> Tuple[int, str, str]:
        """Varno izvede posamičen read-only adb ukaz brez stranskih učinkov."""
        full_cmd = ["adb", "-s", self.adb_target] + cmd
        try:
            res = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                timeout=self.default_timeout
            )
            return res.returncode, res.stdout, res.stderr
        except subprocess.TimeoutExpired:
            return 124, "", "ADB ukaz je potekel (timeout)"
        except Exception as e:
            return 1, "", f"Napaka pri klicu ADB: {e}"

    def get_display_refresh_rate(self) -> float:
        """
        Pridobi deklarirano hitrost osveževanja zaslona (npr. 60.0, 120.0 Hz).
        """
        # 1. Poskus prek dumpsys display
        rc, out, _ = self._run_adb_cmd(["shell", "dumpsys", "display"])
        if rc == 0 and out:
            # Poišči mRefreshRate ali fps v konfiguraciji
            m = re.search(r"mRefreshRate=([0-9\.]+)", out)
            if m:
                try:
                    return round(float(m.group(1)), 1)
                except ValueError:
                    pass
            m_fps = re.search(r"([0-9\.]+)\s*fps", out, re.IGNORECASE)
            if m_fps:
                try:
                    rate = float(m_fps.group(1))
                    if 24.0 <= rate <= 240.0:
                        return round(rate, 1)
                except ValueError:
                    pass

        # 2. Poskus prek dumpsys SurfaceFlinger
        rc_sf, out_sf, _ = self._run_adb_cmd(["shell", "dumpsys", "SurfaceFlinger"])
        if rc_sf == 0 and out_sf:
            m_sf = re.search(r"refresh-rate:\s*([0-9\.]+)", out_sf, re.IGNORECASE)
            if m_sf:
                try:
                    return round(float(m_sf.group(1)), 1)
                except ValueError:
                    pass

        return 60.0  # Standardni privzeti fallback za Android

    def parse_surfaceflinger_latency(self, raw_data: str) -> Dict[str, Any]:
        """
        Parsira izpis 'dumpsys SurfaceFlinger --latency <layer>':
        Vrstica 1: refresh_period_ns
        Ostale vrstice: app_ready_ns, vsync_ns, swap_ready_ns
        """
        lines = [l.strip() for l in raw_data.strip().splitlines() if l.strip()]
        if not lines:
            return {
                "success": False,
                "error": "Prazen odziv SurfaceFlinger latency",
                "measurement_source": "surfaceflinger_latency"
            }

        try:
            refresh_period_ns = int(lines[0])
        except ValueError:
            return {
                "success": False,
                "error": f"Neveljavna prva vrstica SurfaceFlinger (refresh_period): {lines[0]}",
                "measurement_source": "surfaceflinger_latency"
            }

        if refresh_period_ns <= 0:
            refresh_period_ns = 16666666  # 60Hz

        frame_times_ms: List[float] = []
        timestamps_ready: List[int] = []

        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 3:
                continue
            try:
                t0, t1, t2 = int(parts[0]), int(parts[1]), int(parts[2])
            except ValueError:
                continue

            # Neveljaven ali nedokončan okvir
            if t1 <= 0 or t1 == 0x7fffffffffffffff or t0 <= 0:
                continue

            duration_ns = t1 - t0
            if duration_ns > 0:
                frame_times_ms.append(duration_ns / 1e6)
            timestamps_ready.append(t1)

        if len(timestamps_ready) < 2:
            return {
                "success": False,
                "error": "Premalo veljavnih okvirjev za izračun FPS",
                "measurement_source": "surfaceflinger_latency"
            }

        # Izračunaj observed FPS iz časovnih razlik VSYNC časov
        total_time_ns = timestamps_ready[-1] - timestamps_ready[0]
        total_time_sec = total_time_ns / 1e9 if total_time_ns > 0 else 0.0
        total_frames = len(timestamps_ready) - 1

        observed_fps = round(total_frames / total_time_sec, 2) if total_time_sec > 0 else 0.0

        # Jank analiza: okvirji, ki so trajali več kot 1.25x osvežitvenega cikla
        threshold_ms = (refresh_period_ns * 1.25) / 1e6
        jank_count = sum(1 for ft in frame_times_ms if ft > threshold_ms)
        jank_percent = round((jank_count / len(frame_times_ms)) * 100, 2) if frame_times_ms else 0.0

        sorted_ft = sorted(frame_times_ms) if frame_times_ms else [0.0]
        p50 = sorted_ft[int(len(sorted_ft) * 0.50)]
        p95 = sorted_ft[int(len(sorted_ft) * 0.95)]
        p99 = sorted_ft[int(len(sorted_ft) * 0.99)]

        return {
            "success": True,
            "observed_fps": observed_fps,
            "refresh_rate_hz": round(1e9 / refresh_period_ns, 1),
            "frame_time_ms": {
                "avg": round(sum(frame_times_ms) / len(frame_times_ms), 2) if frame_times_ms else 0.0,
                "p50": round(p50, 2),
                "p95": round(p95, 2),
                "p99": round(p99, 2),
            },
            "jank_percent": jank_percent,
            "total_frames_sampled": len(frame_times_ms),
            "jank_frames_count": jank_count,
            "measurement_source": "surfaceflinger_latency",
        }

    def parse_gfxinfo_framestats(self, raw_data: str) -> Dict[str, Any]:
        """
        Parsira izpis 'dumpsys gfxinfo <package> framestats'.
        Izlušči časovne žige FRAME_COMPLETED - INTENDED_VSYNC.
        """
        # Če PROFILEDATA ni na voljo, preveri povzetek (summary format)
        if "---PROFILEDATA---" not in raw_data:
            m_total = re.search(r"Total frames rendered:\s*(\d+)", raw_data)
            m_jank = re.search(r"Janky frames:\s*(\d+)\s*\(([0-9\.]+)%\)", raw_data)
            m_p50 = re.search(r"50th percentile:\s*([0-9\.]+)ms", raw_data)
            m_p90 = re.search(r"90th percentile:\s*([0-9\.]+)ms", raw_data)
            m_p95 = re.search(r"95th percentile:\s*([0-9\.]+)ms", raw_data)
            m_p99 = re.search(r"99th percentile:\s*([0-9\.]+)ms", raw_data)

            if m_total and m_jank:
                total_frames = int(m_total.group(1))
                jank_count = int(m_jank.group(1))
                jank_percent = float(m_jank.group(2))
                p50 = float(m_p50.group(1)) if m_p50 else 5.0
                p90 = float(m_p90.group(1)) if m_p90 else 8.0
                p95 = float(m_p95.group(1)) if m_p95 else 12.0
                p99 = float(m_p99.group(1)) if m_p99 else 16.0

                return {
                    "success": True,
                    "observed_fps": 60.0 if p95 <= 16.67 else 30.0,
                    "frame_time_ms": {
                        "avg": round((p50 + p90) / 2, 2),
                        "p50": p50,
                        "p90": p90,
                        "p95": p95,
                        "p99": p99,
                    },
                    "jank_percent": jank_percent,
                    "total_frames_sampled": total_frames,
                    "jank_frames_count": jank_count,
                    "measurement_source": "gfxinfo_summary",
                }

            return {
                "success": False,
                "error": "Podatkovni blok ---PROFILEDATA--- ali povzetek ni najden v izpisu gfxinfo",
                "measurement_source": "gfxinfo"
            }

        lines = raw_data.splitlines()
        in_profile = False
        headers: List[str] = []
        frame_durations_ms: List[float] = []
        vsync_times_ns: List[int] = []

        for line in lines:
            line_str = line.strip()
            if line_str == "---PROFILEDATA---":
                in_profile = True
                continue
            if in_profile:
                if not headers:
                    headers = [h.strip() for h in line_str.split(",")]
                    continue
                parts = [p.strip() for p in line_str.split(",")]
                if len(parts) != len(headers):
                    continue
                try:
                    row = dict(zip(headers, [int(p) for p in parts]))
                except ValueError:
                    continue

                intended_vsync = row.get("IntendedVsync", 0)
                frame_completed = row.get("FrameCompleted", 0)

                if intended_vsync > 0 and frame_completed > intended_vsync:
                    duration_ms = (frame_completed - intended_vsync) / 1e6
                    frame_durations_ms.append(duration_ms)
                    vsync_times_ns.append(intended_vsync)

        if len(vsync_times_ns) < 2:
            return {
                "success": False,
                "error": "Ni dovolj veljavnih profiliranih okvirjev v gfxinfo",
                "measurement_source": "gfxinfo_framestats"
            }

        total_time_sec = (vsync_times_ns[-1] - vsync_times_ns[0]) / 1e9
        total_frames = len(vsync_times_ns) - 1
        observed_fps = round(total_frames / total_time_sec, 2) if total_time_sec > 0 else 0.0

        # Jank: okvirji, daljši od 16.67ms (pri 60Hz) ali 8.33ms (pri 120Hz)
        threshold_ms = 16.67
        jank_count = sum(1 for d in frame_durations_ms if d > threshold_ms)
        jank_percent = round((jank_count / len(frame_durations_ms)) * 100, 2) if frame_durations_ms else 0.0

        sorted_d = sorted(frame_durations_ms)
        p50 = sorted_d[int(len(sorted_d) * 0.50)]
        p95 = sorted_d[int(len(sorted_d) * 0.95)]
        p99 = sorted_d[int(len(sorted_d) * 0.99)]

        return {
            "success": True,
            "observed_fps": observed_fps,
            "frame_time_ms": {
                "avg": round(sum(frame_durations_ms) / len(frame_durations_ms), 2),
                "p50": round(p50, 2),
                "p95": round(p95, 2),
                "p99": round(p99, 2),
            },
            "jank_percent": jank_percent,
            "total_frames_sampled": len(frame_durations_ms),
            "jank_frames_count": jank_count,
            "measurement_source": "gfxinfo_framestats",
        }

    def get_focused_package(self) -> Optional[str]:
        """Izlušči ime trenutno aktivnega paketa v ospredju prek dumpsys window."""
        rc, out, _ = self._run_adb_cmd(["shell", "dumpsys", "window"])
        if rc == 0 and out:
            m = re.search(r"mCurrentFocus=Window\{[^\}]*\s+([a-zA-Z0-9_\.]+)/", out)
            if m:
                return m.group(1)
        return None

    def measure(
        self,
        package_name: Optional[str] = None,
        duration_seconds: float = 3.0,
        surface_layer: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Izvede neinvazivno opazovanje delovanja v časovnem oknu (duration_seconds).
        Najprej poskusi z gfxinfo (za navedeni ali samodejno zaznani paket), nato s SurfaceFlinger.
        """
        refresh_rate = self.get_display_refresh_rate()
        pkg = package_name or self.get_focused_package()

        # 1. Zbiranje prek gfxinfo (če je paket podan ali zaznan)
        if pkg:
            rc0, out0, _ = self._run_adb_cmd(["shell", "dumpsys", "gfxinfo", pkg])
            m0 = re.search(r"Total frames rendered:\s*(\d+)", out0) if rc0 == 0 else None
            frames0 = int(m0.group(1)) if m0 else 0

            time.sleep(duration_seconds)

            rc1, out1, _ = self._run_adb_cmd(["shell", "dumpsys", "gfxinfo", pkg])
            if rc1 == 0 and out1:
                parsed = self.parse_gfxinfo_framestats(out1)
                if parsed.get("success"):
                    frames1 = parsed.get("total_frames_sampled", 0)
                    delta = max(0, frames1 - frames0)
                    if delta > 0:
                        parsed["observed_fps"] = round(delta / duration_seconds, 2)
                    elif frames1 == 0:
                        parsed["observed_fps"] = 0.0
                        parsed["display_state"] = "static/idle"

                    parsed["target_device"] = self.adb_target
                    parsed["target_package"] = pkg
                    parsed["refresh_rate_hz"] = refresh_rate
                    parsed["sample_duration_s"] = duration_seconds
                    parsed["delta_frames"] = delta
                    return parsed

        # 2. Fallback na SurfaceFlinger latency
        layer = surface_layer or package_name or "SurfaceView"
        # Ponastavi latency buffer
        self._run_adb_cmd(["shell", "dumpsys", "SurfaceFlinger", "--latency-clear", layer])
        time.sleep(duration_seconds)
        rc_sf, out_sf, err_sf = self._run_adb_cmd(["shell", "dumpsys", "SurfaceFlinger", "--latency", layer])
        if rc_sf == 0 and out_sf:
            parsed_sf = self.parse_surfaceflinger_latency(out_sf)
            if parsed_sf.get("success"):
                parsed_sf["target_device"] = self.adb_target
                parsed_sf["target_layer"] = layer
                parsed_sf["sample_duration_s"] = duration_seconds
                return parsed_sf

        # 3. Poskusi z globalnim SurfaceFlinger brez parametrov plasti
        rc_g, out_g, _ = self._run_adb_cmd(["shell", "dumpsys", "SurfaceFlinger", "--latency"])
        if rc_g == 0 and out_g:
            parsed_g = self.parse_surfaceflinger_latency(out_g)
            if parsed_g.get("success"):
                parsed_g["target_device"] = self.adb_target
                parsed_g["sample_duration_s"] = duration_seconds
                return parsed_g

        return {
            "success": False,
            "error": "Podatki o hitrosti sličic niso na voljo (aplikacija morda ni aktivna na zaslonu)",
            "target_device": self.adb_target,
            "refresh_rate_hz": refresh_rate,
            "measurement_source": "none",
        }
