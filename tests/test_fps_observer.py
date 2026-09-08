"""
Testni paket za neodvisen FPS Performance Observer (Read-Only Diagnostic).
Preverja:
1. Pravilno računanje observed_fps, frame_time_ms in jank_percent iz SurfaceFlinger podatkov
2. Pravilno računanje iz gfxinfo framestats podatkov
3. Varnostno izolacijo: opazovalec nima dostopa do ključev, OTA ali ShizukuProvider jedra
"""

import pytest
from core.observers.fps_observer import FpsObserver


def test_fps_observer_surfaceflinger_latency_parser():
    """Preveri natančnost parserja SurfaceFlinger --latency."""
    observer = FpsObserver(adb_target="mock_device")

    # 60Hz osvežitev (16.666.666 ns), 6 zaporednih okvirjev (16.6ms razmika, zadnji janky 35ms)
    t0 = 1000000000
    mock_data = f"""16666666
{t0} {t0 + 16600000} {t0 + 16600000}
{t0 + 16666666} {t0 + 33200000} {t0 + 33200000}
{t0 + 33333332} {t0 + 49800000} {t0 + 49800000}
{t0 + 49999998} {t0 + 66400000} {t0 + 66400000}
{t0 + 66666664} {t0 + 83000000} {t0 + 83000000}
{t0 + 83333330} {t0 + 118000000} {t0 + 118000000}
"""
    res = observer.parse_surfaceflinger_latency(mock_data)
    assert res["success"] is True
    assert res["measurement_source"] == "surfaceflinger_latency"
    assert res["refresh_rate_hz"] == 60.0
    assert 45.0 <= res["observed_fps"] <= 65.0
    assert "avg" in res["frame_time_ms"]
    assert "p95" in res["frame_time_ms"]
    assert res["jank_frames_count"] >= 1
    assert res["jank_percent"] > 0.0


def test_fps_observer_gfxinfo_framestats_parser():
    """Preveri parser za gfxinfo framestats z nanosekundnimi časovnimi žigi."""
    observer = FpsObserver(adb_target="mock_device")

    mock_csv = """
Applications Graphics Acceleration Info:
---PROFILEDATA---
Flags,IntendedVsync,Vsync,OldestInputEvent,NewestInputEvent,HandleInputStart,AnimationStart,PerformTraversalsStart,DrawStart,SyncQueued,SyncStart,IssueDrawCommandsStart,SwapBuffersCompleted,FrameCompleted
0,1000000000,1000000000,0,0,0,0,0,0,0,0,0,1012000000,1012000000
0,1016666666,1016666666,0,0,0,0,0,0,0,0,0,1028000000,1028000000
0,1033333332,1033333332,0,0,0,0,0,0,0,0,0,1045000000,1045000000
0,1049999998,1049999998,0,0,0,0,0,0,0,0,0,1062000000,1062000000
---PROFILEDATA---
"""
    res = observer.parse_gfxinfo_framestats(mock_csv)
    assert res["success"] is True
    assert res["measurement_source"] == "gfxinfo_framestats"
    assert res["total_frames_sampled"] == 4
    assert 50.0 <= res["observed_fps"] <= 65.0
    assert res["frame_time_ms"]["avg"] > 10.0


def test_fps_observer_isolation():
    """
    Varnostna meja: FpsObserver NE SME imeti nobenih uvozov ali referenc
    na privilegirano jedro, KeyStore, ShizukuProvider ali OTA endpoint.
    """
    import ast
    from pathlib import Path

    target_file = Path(__file__).parent.parent / "core" / "observers" / "fps_observer.py"
    tree = ast.parse(target_file.read_text(encoding="utf-8"))

    # Strogo AST preverjanje: modul nima nobenih uvozov iz providers, companion ali security
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert "providers" not in alias.name
                assert "companion" not in alias.name
                assert "security" not in alias.name
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                assert "providers" not in node.module
                assert "companion" not in node.module
                assert "security" not in node.module
