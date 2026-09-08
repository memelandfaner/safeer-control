"""
Ukazna vrstica (CLI) za Safeer Control.
"""

import sys
import hashlib
from pathlib import Path
from core.devices.registry import get_registry
from core.actions.models import ActionRequest
from core.actions.engine import get_action_engine
from scenes.engine import get_scene_engine


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
        elif dev.type.value == "shizuku":
            from core.security.keystore import get_keystore
            ks = get_keystore()
            fp = ks.get_fingerprint(dev.id)
            pair_str = f"🔒 Seznanjeno ({fp})" if fp else "⚠️ Neseznanjeno (Pairing Required)"
            print(f"🛡️ [{dev.name}] ({dev.host}:{dev.port}) — 🟢 Online ({lat_str}) | {pair_str}")
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


def cmd_shizuku(args: list[str]):
    if not args:
        print("Uporaba: safeer-control shizuku [status|pair-pin <pin> [id]|pair [id]|rotate-key [id]|force-stop <pkg>|read-setting <key>|clear-cache <pkg>]")
        return

    sub = args[0].lower()
    reg = get_registry()
    engine = get_action_engine()
    from core.security.keystore import get_keystore
    keystore = get_keystore()

    target_id = "shizuku_companion"
    shizuku_devs = [d for d in reg.list_devices() if d.type.value == "shizuku"]
    if shizuku_devs:
        target_id = shizuku_devs[0].id

    if sub in ("status", "info"):
        prov = reg.get_provider(target_id)
        stat = reg.refresh_status(target_id)
        fp = keystore.get_fingerprint(target_id)
        tls_fp = keystore.get_tls_fingerprint(target_id)
        is_paired = fp is not None
        online = stat.online if stat else False
        transport_tls = getattr(getattr(prov, "transport", None), "use_tls", bool(tls_fp))
        print(f"🛡️ SHIZUKU COMPANION STATUS [{target_id}]:")
        print(f"  • Povezava: {'🟢 Online' if online else '🔴 Offline'}")
        print(f"  • Seznanitev: {'🔒 Seznanjeno' if is_paired else '⚠️ Neseznanjeno'}")
        print(f"  • Prstni odtis ključa (SHA-256): {fp or 'N/A'}")
        print(f"  • Pripet TLS prstni odtis (SHA-256): {tls_fp or 'Brez (nešifrirano)'}")
        print(f"  • Transportni protokol: {'🔒 HTTPS (TLS Pinning)' if transport_tls else '🌐 HTTP (Plaintext)'}")
        if prov and hasattr(prov, "transport") and hasattr(prov.transport, "check_health"):
            healthy = prov.transport.check_health()
            print(f"  • Companion Health: {'🟢 Brezhibno (UID 2000 / rish)' if healthy else '🔴 Neodziven'}")

    elif sub in ("pair-pin", "pin"):
        if len(args) < 2:
            print("Napaka: Navedite 6-mestni PIN. Npr: safeer-control shizuku pair-pin 849201 [device_id]")
            return
        pin = args[1].strip()
        dev_id = args[2] if len(args) > 2 else target_id
        prov = reg.get_provider(dev_id)
        if not prov or not hasattr(prov, "pair_pin"):
            print(f"Napaka: Naprava '{dev_id}' ne podpira seznanitve s PIN-om.")
            return

        print(f"🔐 Povezujem se s Companionom na napravi '{dev_id}' prek TLS...")
        try:
            derived_key, tls_fp = prov.pair_pin(pin)
            key_fp = keystore.compute_fingerprint(derived_key)
            print("=" * 68)
            print(f"✅ USPEŠNA SEZNANITEV NAPRAVE PREK TLS: {dev_id}")
            print(f"  • Pripet TLS prstni odtis (SHA-256): {tls_fp}")
            print(f"  • Prstni odtis 256-bitnega ključa:   {key_fp}")
            print("  • Transport: TLS šifriran (HTTPS) z overjanjem certifikata")
            print("  • Status ključa: Varno shranjen v KeyStore (0600)")
            print("=" * 68)
        except Exception as e:
            print(f"❌ Seznanitev ni uspela: {e}")

    elif sub in ("pair", "seznani"):
        dev_id = args[1] if len(args) > 1 else target_id
        prov = reg.get_provider(dev_id)
        if prov and hasattr(prov, "pair"):
            secret = prov.pair()
        else:
            secret = keystore.get_or_create_key(dev_id)
        fp = keystore.compute_fingerprint(secret)
        print("=" * 68)
        print(f"🔑 ZAČETNA SEZNANITEV NAPRAVE: {dev_id}")
        print(f"  Prstni odtis ključa (SHA-256): {fp}")
        print("-" * 68)
        print("  256-bitni skrivni ključ (prikazan enkrat ob seznanitvi):")
        print(f"  {secret}")
        print("-" * 68)
        print("  NAVODILO ZA VARNO SHRANJEVANJE:")
        print("  1. Ključ varno shranite v datoteko na napravi (dovoljenja 0600):")
        print("     Npr. /data/local/tmp/companion.key")
        print("  2. Zaženite Companion daemon z navedbo datoteke ključa:")
        print("     ./safeer-companion --secret-file /data/local/tmp/companion.key")
        print("=" * 68)

    elif sub in ("rotate-key", "rotiraj-kljuc"):
        dev_id = args[1] if len(args) > 1 and not args[1].startswith("--") else target_id
        show_raw = "--show-secret" in args
        prov = reg.get_provider(dev_id)
        if prov and hasattr(prov, "rotate_secret"):
            new_key = prov.rotate_secret()
        else:
            new_key = keystore.rotate_key(dev_id)
        new_fp = keystore.compute_fingerprint(new_key)
        print(f"🔄 Ključ za napravo '{dev_id}' je bil uspešno rotiran v KeyStore (0600)!")
        print(f"  Novi prstni odtis (SHA-256): {new_fp}")
        if show_raw:
            print(f"  Novi 256-bitni ključ: {new_key}")
        else:
            print("  ℹ️  Skrivni niz je varno shranjen v KeyStore (za izpis uporabite --show-secret).")

    elif sub in ("force-stop", "ustavi"):
        if len(args) < 2:
            print("Napaka: Navedite paket za zaustavitev. Npr: safeer-control shizuku force-stop com.safeer.mobile.browser")
            return
        pkg = args[1]
        res = engine.dispatch(ActionRequest(
            device_id=target_id,
            action="app.force_stop",
            params={"package": pkg}
        ))
        icon = "✅" if res.success else "❌"
        print(f"{icon} Zaustavitev paketa '{pkg}': {res.message}")

    elif sub in ("read-setting", "nastavitev"):
        if len(args) < 2:
            print("Napaka: Navedite ključ nastavitve. Npr: safeer-control shizuku read-setting stay_on_while_plugged_in [global]")
            return
        key = args[1]
        ns = args[2] if len(args) > 2 else "global"
        res = engine.dispatch(ActionRequest(
            device_id=target_id,
            action="settings.read",
            params={"namespace": ns, "key": key}
        ))
        icon = "✅" if res.success else "❌"
        val = res.data.get("value") if res.data else "N/A"
        print(f"{icon} Nastavitev {ns}.{key} = {val} ({res.message})")

    elif sub in ("clear-cache", "pocisti-predpomnilnik"):
        if len(args) < 2:
            print("Napaka: Navedite paket za čiščenje predpomnilnika. Npr: safeer-control shizuku clear-cache com.safeer.mobile.browser")
            return
        pkg = args[1]
        res = engine.dispatch(ActionRequest(
            device_id=target_id,
            action="app.cache_maintenance",
            params={"package": pkg}
        ))
        icon = "✅" if res.success else "❌"
        print(f"{icon} Predpomnilnik paketa '{pkg}': {res.message}")

    elif sub in ("lifecycle", "zivljenjski-cikel", "diag"):
        prov = reg.get_provider(target_id)
        if not prov or not hasattr(prov, "get_lifecycle_status"):
            print(f"Naprava '{target_id}' ne podpira pregleda življenjskega cikla.")
            return
        lc = prov.get_lifecycle_status()
        print("=" * 68)
        print(f"🛡️  SAFEER COMPANION — ŽIVLJENJSKI CIKEL IN ZDRAVJE: {target_id}")
        print(f"  • Status:               {lc.get('status')}")
        print(f"  • Verzija Companion:    v{lc.get('version', '0.9.0')} (Protokol: {lc.get('protocol_version', '1.1')})")
        print(f"  • Uptime / PID:         {lc.get('uptime_seconds', 0)}s / PID {lc.get('pid', 'N/A')}")
        print(f"  • Shizuku stanje:       {lc.get('shizuku_state', 'unknown')} (Dovoljeno: {lc.get('shizuku_permission_granted')})")
        print(f"  • Način izvajanja:      {lc.get('execution_mode', 'rish')}")
        print(f"  • Podrobnosti:          {lc.get('details', '')}")
        print(f"  • TLS Povezava:         {'Aktivna' if lc.get('tls_enabled') else 'Izklopljena'}")
        if lc.get("tls_fingerprint"):
            print(f"  • Pripet TLS odtis:     {lc.get('tls_fingerprint')}")
        print(f"  • Dovoljene zmožnosti:  {', '.join(lc.get('supported_capabilities', []))}")
        print("=" * 68)

    elif sub in ("update", "posodobi"):
        if len(args) < 2:
            print("Napaka: Navedite pot do posodobljene binarne datoteke. Npr: safeer-control shizuku update /tmp/safeer-companion")
            return
        bin_path = Path(args[1]).expanduser().resolve()
        if not bin_path.exists():
            print(f"Napaka: Datoteka {bin_path} ne obstaja!")
            return
        prov = reg.get_provider(target_id)
        if not prov or not hasattr(prov, "update_companion"):
            print(f"Naprava '{target_id}' ne podpira nadzorovanih posodobitev.")
            return
        bin_bytes = bin_path.read_bytes()
        sha = hashlib.sha256(bin_bytes).hexdigest().lower()
        print(f"Pripravljam nadzorovano posodobitev za {target_id}...")
        print(f"  Velikost: {len(bin_bytes)} bajtov")
        print(f"  SHA-256:  {sha}")
        res = prov.update_companion(bin_bytes, restart=True)
        if res.get("success"):
            print(f"✅ Posodobitev uspešna: {res.get('message')}")
            print(f"  Prejšnja verzija: {res.get('old_version')}")
            print(f"  Nova verzija:     {res.get('new_version')}")
        else:
            print(f"❌ Posodobitev ni uspela: {res.get('error_message')}")

    else:
        print(f"Neznan Shizuku ukaz: {sub}")
        print("Razpoložljivi ukazi: status, pair, rotate-key, force-stop, read-setting, clear-cache, lifecycle, update")


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
    elif cmd in ("shizuku", "phone", "telefon", "companion"):
        cmd_shizuku(sys.argv[2:])
    elif cmd in ("scene", "scena", "kino", "cinema"):
        if cmd in ("kino", "cinema"):
            cmd_scene(["cinema"])
        else:
            cmd_scene(sys.argv[2:])
    elif cmd in ("serve", "server", "strežnik"):
        from app.server import start_server
        port = 8990
        if len(sys.argv) >= 3 and sys.argv[2].isdigit():
            port = int(sys.argv[2])
        start_server(port=port)
    else:
        print(f"Neznan ukaz: {cmd}")
        print("Uporaba: safeer-control [status|tv|audio|shizuku|scene|serve]")


if __name__ == "__main__":
    main()
