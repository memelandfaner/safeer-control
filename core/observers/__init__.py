"""
Performance Observers modul za neodvisno diagnostično opazovanje (Read-Only).
Strogo ločen od privilegiranega Companion jedra in brez dostopa do ključev ali OTA.
"""
from core.observers.fps_observer import FpsObserver

__all__ = ["FpsObserver"]
