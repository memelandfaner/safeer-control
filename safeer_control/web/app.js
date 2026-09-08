/**
 * 🛡️ Safeer Control — Odzivni vmesnik (Vanilla JS)
 */

document.addEventListener("DOMContentLoaded", () => {
  // Elementi
  const connIndicator = document.getElementById("connIndicator");
  const connLabel = document.getElementById("connLabel");
  const btnRefresh = document.getElementById("btnRefresh");
  const toastEl = document.getElementById("toast");

  // TV elementi
  const tvName = document.getElementById("tvName");
  const tvStatusText = document.getElementById("tvStatusText");
  const btnTvPower = document.getElementById("btnTvPower");
  const btnTvWake = document.getElementById("btnTvWake");
  const btnTvSleep = document.getElementById("btnTvSleep");

  // D-Pad
  const btnDpadUp = document.getElementById("btnDpadUp");
  const btnDpadDown = document.getElementById("btnDpadDown");
  const btnDpadLeft = document.getElementById("btnDpadLeft");
  const btnDpadRight = document.getElementById("btnDpadRight");
  const btnDpadCenter = document.getElementById("btnDpadCenter");
  const btnTvBack = document.getElementById("btnTvBack");
  const btnTvPlayPause = document.getElementById("btnTvPlayPause");
  const btnTvHome = document.getElementById("btnTvHome");

  // Aplikacije & URL
  const btnOpenSafeer = document.getElementById("btnOpenSafeer");
  const btnOpenSmarttube = document.getElementById("btnOpenSmarttube");
  const btnOpenStreamtv = document.getElementById("btnOpenStreamtv");
  const btnOpenXplore = document.getElementById("btnOpenXplore");
  const formSendUrl = document.getElementById("formSendUrl");
  const inputUrl = document.getElementById("inputUrl");

  // Vhodi & Posnetek
  const btnInputPc = document.getElementById("btnInputPc");
  const btnInputPs5 = document.getElementById("btnInputPs5");
  const btnTvScreenshot = document.getElementById("btnTvScreenshot");
  const screenshotBox = document.getElementById("screenshotBox");

  // Avdio elementi
  const audioName = document.getElementById("audioName");
  const audioStatusText = document.getElementById("audioStatusText");
  const btnAudioUnmute = document.getElementById("btnAudioUnmute");
  const volSlider = document.getElementById("volSlider");
  const volVal = document.getElementById("volVal");
  const volPresets = document.querySelectorAll(".btn-vol-preset");

  // Naprave & Scene
  const devicesList = document.getElementById("devicesList");
  const scenesList = document.getElementById("scenesList");

  // 1. ZAVIHKA PREKLAPLJANJE
  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".tab-pane").forEach((p) => p.classList.remove("active"));

      btn.classList.add("active");
      const tabId = btn.getAttribute("data-tab");
      const targetPane = document.getElementById(tabId);
      if (targetPane) targetPane.classList.add("active");
    });
  });

  // 2. TOAST SPOROČILA
  let toastTimer = null;
  function showToast(msg) {
    if (toastTimer) clearTimeout(toastTimer);
    toastEl.textContent = msg;
    toastEl.classList.add("show");
    toastTimer = setTimeout(() => {
      toastEl.classList.remove("show");
    }, 2500);
  }

  // 3. API KLICI
  async function apiAction(deviceId, action, params = {}) {
    try {
      const res = await fetch("/api/action", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          device_id: deviceId,
          action: action,
          params: params,
        }),
      });
      const data = await res.json();
      if (data.success) {
        showToast(`✅ ${data.message || "Uspešno izvedeno"}`);
      } else {
        showToast(`⚠️ ${data.message || "Napaka pri izvedbi"}`);
      }
      return data;
    } catch (e) {
      showToast(`❌ Napaka povezave: ${e.message}`);
      return { success: false, message: e.message };
    }
  }

  // 4. OSVEŽEVANJE STANJA NAPRAV
  async function refreshDevices() {
    try {
      const res = await fetch("/api/devices");
      if (!res.ok) throw new Error("Napaka pri pridobivanju naprav");
      const devices = await res.json();

      connIndicator.classList.add("online");
      connLabel.textContent = "Povezano";

      renderDevices(devices);
    } catch (e) {
      connIndicator.classList.remove("online");
      connLabel.textContent = "Brez povezave";
    }
  }

  function renderDevices(devices) {
    devicesList.innerHTML = "";

    devices.forEach((dev) => {
      const isOnline = dev.status && dev.status.online;
      const lat = dev.status && dev.status.latency_ms >= 0 ? `${dev.status.latency_ms.toFixed(1)} ms` : "Nedosegljiv";

      // Posodobi TV kartico
      if (dev.type === "android_tv") {
        tvName.textContent = dev.name;
        const powerStr = dev.status.power_on ? "Zaslon Prižgan" : "V mirovanju";
        tvStatusText.textContent = isOnline ? `🟢 Online (${lat}) • ${powerStr}` : "🔴 Brez povezave";
      }

      // Posodobi JBL kartico
      if (dev.type === "audio_soundbar") {
        audioName.textContent = dev.name;
        const vol = dev.status && dev.status.volume !== null ? `${dev.status.volume} %` : "-- %";
        const muteStr = dev.status.muted ? "Utišan" : "Aktiven";
        audioStatusText.textContent = isOnline ? `🟢 Online (${lat}) • ${muteStr}` : "🔴 Brez povezave";

        if (dev.status && dev.status.volume !== null && !isDraggingVolume) {
          volSlider.value = dev.status.volume;
          volVal.textContent = vol;
        }
      }

      // Seznam vseh naprav
      const item = document.createElement("div");
      item.className = "device-item";
      const icon = dev.type === "android_tv" ? "📺" : dev.type === "audio_soundbar" ? "🔊" : "📱";
      item.innerHTML = `
        <div class="device-item-left">
          <span class="device-icon">${icon}</span>
          <div>
            <div class="device-name">${dev.name}</div>
            <div class="device-status-text">${dev.host} • ${lat}</div>
          </div>
        </div>
        <span class="device-badge ${isOnline ? "online" : "offline"}">
          ${isOnline ? "ONLINE" : "OFFLINE"}
        </span>
      `;
      devicesList.appendChild(item);
    });
  }

  // 5. DOGODKI DALJINCA
  btnTvPower.addEventListener("click", () => apiAction("living_room_tv", "power"));
  btnTvWake.addEventListener("click", () => apiAction("living_room_tv", "wake"));
  btnTvSleep.addEventListener("click", () => apiAction("living_room_tv", "sleep"));

  // D-Pad ključni dogodki (Android KeyCodes: Up 19, Down 20, Left 21, Right 22, OK 23)
  btnDpadUp.addEventListener("click", () => apiAction("living_room_tv", "key", { keycode: 19 }));
  btnDpadDown.addEventListener("click", () => apiAction("living_room_tv", "key", { keycode: 20 }));
  btnDpadLeft.addEventListener("click", () => apiAction("living_room_tv", "key", { keycode: 21 }));
  btnDpadRight.addEventListener("click", () => apiAction("living_room_tv", "key", { keycode: 22 }));
  btnDpadCenter.addEventListener("click", () => apiAction("living_room_tv", "key", { keycode: 23 }));

  btnTvBack.addEventListener("click", () => apiAction("living_room_tv", "key", { keycode: 4 }));
  btnTvPlayPause.addEventListener("click", () => apiAction("living_room_tv", "play_pause"));
  btnTvHome.addEventListener("click", () => apiAction("living_room_tv", "key", { keycode: 3 }));

  // Aplikacije
  btnOpenSafeer.addEventListener("click", () => apiAction("living_room_tv", "open_browser"));
  btnOpenSmarttube.addEventListener("click", () => apiAction("living_room_tv", "open_smarttube"));
  btnOpenStreamtv.addEventListener("click", () => apiAction("living_room_tv", "open_streamtv"));
  btnOpenXplore.addEventListener("click", () => apiAction("living_room_tv", "open_xplore_tv"));

  // Pošiljanje URL-ja
  formSendUrl.addEventListener("submit", (e) => {
    e.preventDefault();
    const url = inputUrl.value.trim();
    if (url) {
      apiAction("living_room_tv", "open_url", { url: url });
      inputUrl.value = "";
    }
  });

  // HDMI vhodi
  btnInputPc.addEventListener("click", () => apiAction("living_room_tv", "switch_input", { input: "pc" }));
  btnInputPs5.addEventListener("click", () => apiAction("living_room_tv", "switch_input", { input: "ps5" }));

  // Posnetek zaslona
  btnTvScreenshot.addEventListener("click", async () => {
    screenshotBox.innerHTML = "<span>Zajemam sliko televizorja...</span>";
    const ts = Date.now();
    const img = new Image();
    img.src = `/api/tv/screenshot?t=${ts}`;
    img.onload = () => {
      screenshotBox.innerHTML = "";
      screenshotBox.appendChild(img);
      showToast("📸 Posnetek zaslona osvežen");
    };
    img.onerror = () => {
      screenshotBox.innerHTML = '<span class="preview-hint">Zajem ni uspel. Ali je televizor prižgan?</span>';
      showToast("⚠️ Zajem zaslona ni uspel");
    };
  });

  // 6. AVDIO KRMILJENJE
  btnAudioUnmute.addEventListener("click", () => apiAction("living_room_audio", "unmute"));

  let isDraggingVolume = false;
  let volDebounceTimer = null;

  volSlider.addEventListener("input", (e) => {
    isDraggingVolume = true;
    const val = e.target.value;
    volVal.textContent = `${val} %`;

    if (volDebounceTimer) clearTimeout(volDebounceTimer);
    volDebounceTimer = setTimeout(() => {
      apiAction("living_room_audio", "set_volume", { volume: parseInt(val, 10) });
      isDraggingVolume = false;
    }, 250);
  });

  volPresets.forEach((btn) => {
    btn.addEventListener("click", () => {
      const targetVol = parseInt(btn.getAttribute("data-vol"), 10);
      volSlider.value = targetVol;
      volVal.textContent = `${targetVol} %`;
      apiAction("living_room_audio", "set_volume", { volume: targetVol });
    });
  });

  // 7. SCENE
  document.querySelectorAll(".btn-scene-run").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const sceneId = btn.getAttribute("data-scene");
      btn.disabled = true;
      btn.textContent = "Izvajam...";
      try {
        const res = await fetch(`/api/scenes/${sceneId}/execute`, { method: "POST" });
        const results = await res.json();
        showToast(`🎬 Scena '${sceneId}' zaključena`);
      } catch (e) {
        showToast(`❌ Napaka pri zagonu scene: ${e.message}`);
      } finally {
        btn.disabled = false;
        btn.textContent = "Zaženi";
        refreshDevices();
      }
    });
  });

  // 8. OSVEŽEVALNIK IN SAMODEJNA ZANKA
  btnRefresh.addEventListener("click", () => {
    refreshDevices();
    showToast("Osvežujem podatke...");
  });

  // Začetni klic in periodično osveževanje vsakih 3,5 sekunde
  refreshDevices();
  setInterval(refreshDevices, 3500);
});
