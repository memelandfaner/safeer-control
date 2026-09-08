"""
Ukazna vrstica (CLI) za Safeer Control.
Omogoča hiter nadzor, diagnostiko in proženje scen neposredno iz terminala.
"""

import sys
from safeer_control.core.registry import get_registry
from safeer_control.core.action_engine import get_action_engine
from safeer_control.core.scene_engine import get_scene_engine
from safeer_control.core.models import ActionRequest


def print_header():
    print("=" * 68)
    print(" 🛡️  SAFEER CONTROL — NADZORNA PLOŠČA NAPRAV")
    print("=" * 68)


def cmd_status():
    print_header()
    reg = get_registry()
    devices = reg.list_devices()

    for dev in devices:
        stat = reg.refresh_status(dev.id)
        if not stat or not stat.online:
            print(f"🔴 [{dev.name}] ({dev.host}) — Brez povezave")
            continue

        lat_str = f"{stat.latency_ms:.1f} ms"
        if dev.type.value == "android_tv":
            p_str = "🟢 Zaslon PRIŽGAN" if stat.power_on else "🟡 V mirovanju (Sleep)"
            print(f"📺 [{dev.name}] ({dev.host}) — 🟢 Online ({lat_str}) | {p_str}")
        elif dev.type.value == "audio_soundbar":
            m_str = "🔇 Utišan (Muted)" if stat.muted else "🔊 Aktiven"
            vol_str = f"{stat.volume} %" if stat.volume is not None else "N/A"
            print(f"🔊 [{dev.name}] ({dev.host}) — 🟢 Online ({lat_str}) | Glasnost: {vol_str} | {m_str}")
        else:
            print(f"🟢 [{dev.name}] ({dev.host}) — Online ({lat_str})")

    print("=" * 68)


def cmd_tv(args: list[str]):
    if not args:
        print("Uporaba: safeer-control tv [power|wake|sleep|browser|url <link>|smarttube <query>|xplore [kanal]|pc|ps5]")
        return

    sub = args[0].lower()
    engine = get_action_engine()

    if sub in ("power", "vklop", "izklop"):
        res = engine.dispatch(ActionRequest(device_id="living_room_tv", action="power"))
        print(f"📺 TV Power: {res.message}")
    elif sub in ("wake", "zbudi"):
        res = engine.dispatch(ActionRequest(device_id="living_room_tv", action="wake"))
        print(f"📺 TV Wake: {res.message}")
    elif sub in ("sleep", "spanje"):
        res = engine.dispatch(ActionRequest(device_id="living_room_tv", action="sleep"))
        print(f"📺 TV Sleep: {res.message}")
    elif sub in ("browser", "brskalnik"):
        res = engine.dispatch(ActionRequest(device_id="living_room_tv", action="open_browser"))
        print(f"📺 Safeer Browser: {res.message}")
    elif sub == "url" and len(args) >= 2:
        url = args[1]
        res = engine.dispatch(ActionRequest(device_id="living_room_tv", action="open_url", params={"url": url}))
        print(f"📺 Open URL: {res.message}")
    elif sub in ("smarttube", "youtube"):
        query = " ".join(args[1:]) if len(args) > 1 else ""
        res = engine.dispatch(ActionRequest(device_id="living_room_tv", action="open_smarttube", params={"query": query}))
        print(f"📺 SmartTube: {res.message}")
    elif sub in ("xplore", "xploretv"):
        ch = int(args[1]) if len(args) > 1 and args[1].isdigit() else 0
        params = {"channel": ch} if ch > 0 else {}
        res = engine.dispatch(ActionRequest(device_id="living_room_tv", action="open_xplore_tv", params=params))
        print(f"📺 Xplore TV: {res.message}")
    elif sub == "pc":
        res = engine.dispatch(ActionRequest(device_id="living_room_tv", action="switch_input", params={"input": "pc"}))
        print(f"📺 TV Vhod PC: {res.message}")
    elif sub == "ps5":
        res = engine.dispatch(ActionRequest(device_id="living_room_tv", action="switch_input", params={"input": "ps5"}))
        print(f"📺 TV Vhod PS5: {res.message}")
    else:
        print(f"Neznan TV ukaz: {sub}")


def cmd_audio(args: list[str]):
    if not args:
        print("Uporaba: safeer-control audio [volume <0-100>|unmute|mute]")
        return

    sub = args[0].lower()
    engine = get_action_engine()

    if sub in ("volume", "vol", "glasnost") and len(args) >= 2:
        try:
            vol = int(args[1])
            res = engine.dispatch(ActionRequest(device_id="living_room_audio", action="set_volume", params={"volume": vol}))
            print(f"🔊 JBL Glasnost: {res.message}")
        except ValueError:
            print("Napaka: Glasnost mora biti število med 0 in 100.")
    elif sub in ("unmute", "odkleni"):
        res = engine.dispatch(ActionRequest(device_id="living_room_audio", action="unmute"))
        print(f"🔊 JBL Unmute: {res.message}")
    elif sub in ("mute", "utisaj"):
        res = engine.dispatch(ActionRequest(device_id="living_room_audio", action="mute"))
        print(f"🔊 JBL Mute: {res.message}")
    else:
        print(f"Neznan avdio ukaz: {sub}")


def cmd_scene(args: list[str]):
    scene_engine = get_scene_engine()
    if not args:
        print("Razpoložljive scene:")
        for s in scene_engine.list_scenes():
            print(f"  • {s.id:12} — {s.name} ({s.description})")
        return

    scene_id = args[0].lower()
    print(f"🚀 Izvajam sceno '{scene_id}'...")
    results = scene_engine.execute_scene(scene_id)
    for r in results:
        status_icon = "✅" if r.success else "❌"
        print(f"  {status_icon} [{r.device_id or 'SCENA'}] {r.action}: {r.message}")


def main():
    if len(sys.argv) < 2:
        cmd_status()
        return

    cmd = sys.argv[1].lower()
    if cmd in ("status", "stanje", "info"):
        cmd_status()
    elif cmd == "tv":
        cmd_tv(sys.argv[2:])
    elif cmd in ("audio", "jbl", "zvok"):
        cmd_audio(sys.argv[2:])
    elif cmd in ("scene", "scena", "kino", "cinema"):
        if cmd in ("kino", "cinema"):
            cmd_scene(["cinema"])
        else:
            cmd_scene(sys.argv[2:])
    else:
        print(f"Neznan ukaz: {cmd}")
        print("Uporaba: safeer-control [status|tv|audio|scene]")


if __name__ == "__main__":
    main()
