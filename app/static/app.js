/**
 * 🛡️ Safeer Control — Odzivni vmesnik (Vanilla JS)
 * V0.2.1 Hardened: Kratkotrajne seje (Session Tokens), BLOB zajem slik brez žetonov v URL-jih.
 */

document.addEventListener("DOMContentLoaded", () => {
  // 1. Upravljanje kratkotrajne seje (Session Storage)
  // SKRIVNOSTI NIKOLI NE BERE IZ URL-ja (?token= prepovedan)!
  let sessionToken = sessionStorage.getItem("safeer_session") || "";

  function getAuthHeaders(extraHeaders = {}) {
    const headers = { ...extraHeaders };
    if (sessionToken) {
      headers["X-Safeer-Session"] = sessionToken;
    }
    return headers;
  }

  async function ensureSession() {
    if (sessionToken) {
      try {
        const check = await fetch("/api/auth/verify", {
          method: "POST",
          headers: getAuthHeaders(),
        });
        if (check.ok) return true;
      } catch (e) {}
    }

    const entered = prompt("🔒 Vnesite Safeer Auth Token za začasno sejo:");
    if (!entered) return false;

    try {
      const res = await fetch("/api/auth/session", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: entered.trim() }),
      });
      if (res.ok) {
        const data = await res.json();
        sessionToken = data.session_token;
        sessionStorage.setItem("safeer_session", sessionToken);
        showToast("🔑 Seja uspešno vzpostavljena");
        refreshDevices();
        return true;
      } else {
        showToast("❌ Neveljaven žeton");
        return false;
      }
    } catch (e) {
      showToast(`❌ Napaka pri prijavi: ${e.message}`);
      return false;
    }
  }

  // Elementi
  const connIndicator = document.getElementById("connIndicator");
  const connLabel = document.getElementById("connLabel");
  const btnRefresh = document.getElementById("btnRefresh");
  const toastEl = document.getElementById("toast");

  // TV elementi
  const tvName = document.getElementById("tvName");
  const tvStatusText = document.getElementById("tvStatusText");
  const tvPowerBadge = document.getElementById("tvPowerBadge");
  const tvAppBadge = document.getElementById("tvAppBadge");
  const btnTvPair = document.getElementById("btnTvPair");
  const btnTvPower = document.getElementById("btnTvPower");
  const btnTvWake = document.getElementById("btnTvWake");
  const btnTvSleep = document.getElementById("btnTvSleep");

  // Glavni nadzor: Nazaj, Pavza, Domov
  const btnTvBack = document.getElementById("btnTvBack");
  const btnTvPlayPause = document.getElementById("btnTvPlayPause");
  const btnTvHome = document.getElementById("btnTvHome");

  // D-Pad
  const btnDpadUp = document.getElementById("btnDpadUp");
  const btnDpadDown = document.getElementById("btnDpadDown");
  const btnDpadLeft = document.getElementById("btnDpadLeft");
  const btnDpadRight = document.getElementById("btnDpadRight");
  const btnDpadCenter = document.getElementById("btnDpadCenter");

  // Safeer Browser Hub & Povezave
  const btnOpenSafeer = document.getElementById("btnOpenSafeer");
  const formSendUrl = document.getElementById("formSendUrl");
  const inputUrl = document.getElementById("inputUrl");
  const chips = document.querySelectorAll(".chip");

  // Vhodi & Posnetek
  const btnInputPc = document.getElementById("btnInputPc");
  const btnInputPs5 = document.getElementById("btnInputPs5");
  const btnTvScreenshot = document.getElementById("btnTvScreenshot");
  const screenshotBox = document.getElementById("screenshotBox");

  // Avdio elementi
  const audioName = document.getElementById("audioName");
  const audioStatusText = document.getElementById("audioStatusText");
  const audioMuteBadge = document.getElementById("audioMuteBadge");
  const btnAudioUnmute = document.getElementById("btnAudioUnmute");
  const btnAudioMute = document.getElementById("btnAudioMute");
  const btnVolDown = document.getElementById("btnVolDown");
  const btnVolUp = document.getElementById("btnVolUp");
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
  async function apiAction(deviceId, action, params = {}, retryAuth = true) {
    try {
      const res = await fetch("/api/action", {
        method: "POST",
        headers: getAuthHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({
          device_id: deviceId,
          action: action,
          params: params,
        }),
      });

      if (res.status === 401 && retryAuth) {
        const ok = await ensureSession();
        if (ok) {
          return apiAction(deviceId, action, params, false);
        }
        return { success: false, message: "Zahtevana avtentikacija" };
      }

      const data = await res.json();
      if (data.success) {
        showToast(`✅ ${data.message || "Uspešno izvedeno"}`);
      } else {
        showToast(`⚠️ ${data.message || "Napaka pri izvedbi"}`);
      }
      refreshDevices();
      return data;
    } catch (e) {
      showToast(`❌ Napaka povezave: ${e.message}`);
      return { success: false, message: e.message };
    }
  }

  // 4. OSVEŽEVANJE STANJA NAPRAV
  async function refreshDevices() {
    try {
      const res = await fetch("/api/devices", {
        headers: getAuthHeaders(),
      });
      if (res.status === 401) {
        connIndicator.classList.remove("online");
        connLabel.textContent = "Zahtevana avtentikacija";
        return;
      }
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
        tvStatusText.textContent = isOnline ? `🟢 Online (${lat}) • ${dev.host}` : "🔴 Brez povezave";

        if (tvPowerBadge) {
          tvPowerBadge.textContent = dev.status.power_on ? "⚡ Prižgan" : "🌙 V mirovanju";
          tvPowerBadge.className = `tv-badge ${dev.status.power_on ? "awake" : ""}`;
        }

        if (tvAppBadge && dev.status.active_app) {
          tvAppBadge.textContent = `📱 ${dev.status.active_app}`;
          tvAppBadge.className = "tv-badge active-app";
        }

        if (btnTvPair && dev.status.extra) {
          const isAdb = dev.status.extra.adb_connected;
          btnTvPair.textContent = isAdb ? "🟢 Seznanjeno (ADB)" : "🔒 Seznani (ADB)";
        }
      }

      // Posodobi JBL kartico
      if (dev.type === "audio_soundbar") {
        audioName.textContent = dev.name;
        const vol = dev.status && dev.status.volume !== null ? `${dev.status.volume} %` : "-- %";
        const isMuted = dev.status && dev.status.muted;
        const muteStr = isMuted ? "Utišan" : "Aktiven";
        audioStatusText.textContent = isOnline ? `🟢 Online (${lat}) • ${muteStr}` : "🔴 Brez povezave";

        if (audioMuteBadge) {
          audioMuteBadge.textContent = isMuted ? "🔇 Utišan" : "🔊 Aktiven";
          audioMuteBadge.className = `tv-badge ${isMuted ? "btn-mute-alt" : "awake"}`;
        }

        if (dev.status && dev.status.volume !== null && !isDraggingVolume) {
          volSlider.value = dev.status.volume;
          volVal.textContent = vol;
        }
      }

      // Posodobi Shizuku kartico
      if (dev.type === "shizuku") {
        refreshShizukuStatus(dev);
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
  btnTvPair.addEventListener("click", () => apiAction("living_room_tv", "pair"));
  btnTvPower.addEventListener("click", () => apiAction("living_room_tv", "power"));
  btnTvWake.addEventListener("click", () => apiAction("living_room_tv", "wake"));
  btnTvSleep.addEventListener("click", () => apiAction("living_room_tv", "sleep"));

  // Glavni nadzor: Nazaj, Pavza, Domov
  btnTvBack.addEventListener("click", () => apiAction("living_room_tv", "back"));
  btnTvPlayPause.addEventListener("click", () => apiAction("living_room_tv", "play_pause"));
  btnTvHome.addEventListener("click", () => apiAction("living_room_tv", "home"));

  // D-Pad krmilnik
  btnDpadUp.addEventListener("click", () => apiAction("living_room_tv", "key", { keycode: 19 }));
  btnDpadDown.addEventListener("click", () => apiAction("living_room_tv", "key", { keycode: 20 }));
  btnDpadLeft.addEventListener("click", () => apiAction("living_room_tv", "key", { keycode: 21 }));
  btnDpadRight.addEventListener("click", () => apiAction("living_room_tv", "key", { keycode: 22 }));
  btnDpadCenter.addEventListener("click", () => apiAction("living_room_tv", "key", { keycode: 23 }));

  // Safeer Browser
  btnOpenSafeer.addEventListener("click", () => apiAction("living_room_tv", "open_browser"));

  // Hitri čipi
  chips.forEach((chip) => {
    chip.addEventListener("click", () => {
      const url = chip.getAttribute("data-url");
      inputUrl.value = url;
      apiAction("living_room_tv", "open_url", { url: url });
    });
  });

  // Obrazec pošiljanja URL-ja
  formSendUrl.addEventListener("submit", (e) => {
    e.preventDefault();
    const url = inputUrl.value.trim();
    if (url) {
      apiAction("living_room_tv", "open_url", { url: url });
      inputUrl.value = "";
    }
  });

  // Dodatne aplikacije
  const btnOpenSmarttube = document.getElementById("btnOpenSmarttube");
  const btnOpenStreamtv = document.getElementById("btnOpenStreamtv");
  const btnOpenXplore = document.getElementById("btnOpenXplore");
  if (btnOpenSmarttube) btnOpenSmarttube.addEventListener("click", () => apiAction("living_room_tv", "open_smarttube"));
  if (btnOpenStreamtv) btnOpenStreamtv.addEventListener("click", () => apiAction("living_room_tv", "open_streamtv"));
  if (btnOpenXplore) btnOpenXplore.addEventListener("click", () => apiAction("living_room_tv", "open_xplore_tv"));

  // HDMI vhodi
  btnInputPc.addEventListener("click", () => apiAction("living_room_tv", "switch_input", { input: "pc" }));
  btnInputPs5.addEventListener("click", () => apiAction("living_room_tv", "switch_input", { input: "ps5" }));

  // Posnetek zaslona (VARNO: headers + BLOB, brez žetona v URL-ju!)
  btnTvScreenshot.addEventListener("click", async () => {
    screenshotBox.innerHTML = "<span>Zajemam sliko televizorja...</span>";
    try {
      const res = await fetch("/api/tv/screenshot", {
        headers: getAuthHeaders(),
      });
      if (res.status === 401) {
        const ok = await ensureSession();
        if (ok) {
          btnTvScreenshot.click();
          return;
        }
      }
      if (!res.ok) throw new Error("Zajem ni uspel");
      const blob = await res.blob();
      const objectUrl = URL.createObjectURL(blob);
      const img = new Image();
      img.src = objectUrl;
      img.onload = () => {
        screenshotBox.innerHTML = "";
        screenshotBox.appendChild(img);
        showToast("📸 Posnetek zaslona osvežen");
      };
    } catch (e) {
      screenshotBox.innerHTML = '<span class="preview-hint">Zajem ni uspel. Ali je televizor prižgan?</span>';
      showToast("⚠️ Zajem zaslona ni uspel");
    }
  });

  // 6. AVDIO KRMILJENJE
  if (btnAudioUnmute) btnAudioUnmute.addEventListener("click", () => apiAction("living_room_audio", "unmute"));
  if (btnAudioMute) btnAudioMute.addEventListener("click", () => apiAction("living_room_audio", "mute"));
  if (btnVolDown) btnVolDown.addEventListener("click", () => apiAction("living_room_audio", "volume_down", { step: 5 }));
  if (btnVolUp) btnVolUp.addEventListener("click", () => apiAction("living_room_audio", "volume_up", { step: 5 }));

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
        const res = await fetch(`/api/scenes/${sceneId}/execute`, {
          method: "POST",
          headers: getAuthHeaders(),
        });
        if (res.status === 401) {
          const ok = await ensureSession();
          if (ok) {
            btn.click();
            return;
          }
        }
        const report = await res.json();
        if (report.status === "COMPLETED") {
          showToast(`🎬 Scena '${sceneId}' USPEŠNA (${(report.elapsed_ms / 1000).toFixed(1)} s)`);
        } else if (report.status === "ROLLED_BACK") {
          showToast(`⚠️ Scena '${sceneId}' prekinjena — stanje povrnjeno (Rollback)`);
        } else {
          showToast(`❌ Scena '${sceneId}' odpovedala: ${report.error_message || report.status}`);
        }
      } catch (e) {
        showToast(`❌ Napaka pri zagonu scene: ${e.message}`);
      } finally {
        btn.disabled = false;
        btn.textContent = "Zaženi";
        refreshDevices();
      }
    });
  });

  // 8. SHIZUKU COMPANION & PAIRING UX
  const shizukuName = document.getElementById("shizukuName");
  const shizukuStatusText = document.getElementById("shizukuStatusText");
  const shizukuPairBadge = document.getElementById("shizukuPairBadge");
  const shizukuHealthBadge = document.getElementById("shizukuHealthBadge");
  const shizukuFingerprintBadge = document.getElementById("shizukuFingerprintBadge");
  const btnShizukuPairModal = document.getElementById("btnShizukuPairModal");
  const btnShizukuRotateKey = document.getElementById("btnShizukuRotateKey");

  const pairingModal = document.getElementById("pairingModal");
  const btnClosePairingModal = document.getElementById("btnClosePairingModal");
  const btnDismissPairModal = document.getElementById("btnDismissPairModal");
  const btnConfirmGeneratePair = document.getElementById("btnConfirmGeneratePair");
  const displaySecretKey = document.getElementById("displaySecretKey");
  const btnCopySecretKey = document.getElementById("btnCopySecretKey");
  const pairingCodeBox = document.getElementById("pairingCodeBox");

  const selectForceStopPkg = document.getElementById("selectForceStopPkg");
  const btnExecForceStop = document.getElementById("btnExecForceStop");
  const inputSettingKey = document.getElementById("inputSettingKey");
  const selectSettingNs = document.getElementById("selectSettingNs");
  const btnExecReadSetting = document.getElementById("btnExecReadSetting");
  const settingResultBox = document.getElementById("settingResultBox");
  const settingResultText = document.getElementById("settingResultText");
  const inputCachePkg = document.getElementById("inputCachePkg");
  const btnExecClearCache = document.getElementById("btnExecClearCache");

  async function refreshShizukuStatus(dev) {
    if (!shizukuName) return;
    const targetId = dev ? dev.id : "shizuku_companion";
    try {
      const res = await fetch(`/api/devices/${targetId}/pairing`, {
        headers: getAuthHeaders(),
      });
      if (res.ok) {
        const data = await res.json();
        if (data.is_paired) {
          shizukuPairBadge.textContent = "🔒 Seznanjeno (256-bit HMAC)";
          shizukuPairBadge.className = "tv-badge awake";
          if (shizukuFingerprintBadge) {
            shizukuFingerprintBadge.textContent = data.fingerprint ? `Odtis: ${data.fingerprint}` : "Odtis: Aktiven";
          }
        } else {
          shizukuPairBadge.textContent = "⚠️ Neseznanjeno";
          shizukuPairBadge.className = "tv-badge";
          if (shizukuFingerprintBadge) {
            shizukuFingerprintBadge.textContent = "Odtis: Ni seznanjen";
          }
        }

        const isHealthy = data.health && data.health.healthy;
        shizukuHealthBadge.textContent = isHealthy ? "🟢 Companion: Aktiven (rish)" : "🔴 Companion: Neodziven";
        shizukuHealthBadge.className = `tv-badge ${isHealthy ? "awake" : ""}`;

        if (dev) {
          shizukuName.textContent = dev.name;
          shizukuStatusText.textContent = dev.status && dev.status.online ? `🟢 Online • ${dev.host}:${dev.port}` : "🔴 Brez povezave";
        }
      }
    } catch (e) {}
  }

  if (btnShizukuPairModal) {
    btnShizukuPairModal.addEventListener("click", async () => {
      pairingModal.style.display = "flex";
      try {
        const res = await fetch("/api/devices/shizuku_companion/pair", {
          method: "POST",
          headers: getAuthHeaders(),
        });
        if (res.ok) {
          const data = await res.json();
          displaySecretKey.value = data.secret_key;
          pairingCodeBox.textContent = `256-bitni ključ (prikazan le enkrat ob seznanitvi):\n${data.secret_key}\n\nPrstni odtis (SHA-256): ${data.fingerprint}\n\nKljuč varno shranite v datoteko na napravi (0600):\n./safeer-companion --secret-file /data/local/tmp/companion.key`;
          refreshShizukuStatus();
          showToast("🔑 Seznanitveni ključ generiran");
        }
      } catch (e) {
        showToast(`❌ Napaka pri seznanitvi: ${e.message}`);
      }
    });
  }

  if (btnClosePairingModal) btnClosePairingModal.addEventListener("click", () => pairingModal.style.display = "none");
  if (btnDismissPairModal) btnDismissPairModal.addEventListener("click", () => pairingModal.style.display = "none");

  if (btnCopySecretKey) {
    btnCopySecretKey.addEventListener("click", () => {
      if (displaySecretKey.value) {
        navigator.clipboard.writeText(displaySecretKey.value);
        showToast("📋 Ključ kopiran v odložišče");
      }
    });
  }

  const inputPairPin = document.getElementById("inputPairPin");
  const btnSubmitPairPin = document.getElementById("btnSubmitPairPin");
  if (btnSubmitPairPin) {
    btnSubmitPairPin.addEventListener("click", async () => {
      const pin = inputPairPin ? inputPairPin.value.trim() : "";
      if (!pin || pin.length !== 6) {
        showToast("⚠️ Vnesite 6-mestni PIN iz naprave");
        return;
      }
      try {
        btnSubmitPairPin.disabled = true;
        btnSubmitPairPin.textContent = "⏳ Seznanjam...";
        const res = await fetch("/api/devices/shizuku_companion/pair-pin", {
          method: "POST",
          headers: getAuthHeaders({ "Content-Type": "application/json" }),
          body: JSON.stringify({ pin: pin }),
        });
        const data = await res.json();
        if (res.ok) {
          const shortFp = data.tls_fingerprint ? data.tls_fingerprint.substring(0, 16) + "..." : "OK";
          showToast(`✅ Seznanjeno prek TLS! Odtis: ${shortFp}`);
          pairingModal.style.display = "none";
          refreshShizukuStatus();
        } else {
          showToast(`❌ Seznanitev zavrnjena: ${data.detail || "Napačen ali potekel PIN"}`);
        }
      } catch (e) {
        showToast(`❌ Napaka pri seznanitvi: ${e.message}`);
      } finally {
        btnSubmitPairPin.disabled = false;
        btnSubmitPairPin.textContent = "🔐 Seznani s PIN-om (TLS)";
      }
    });
  }

  if (btnConfirmGeneratePair) {
    btnConfirmGeneratePair.addEventListener("click", async () => {
      try {
        const res = await fetch("/api/devices/shizuku_companion/pair", {
          method: "POST",
          headers: getAuthHeaders(),
        });
        if (res.ok) {
          const data = await res.json();
          displaySecretKey.value = data.secret_key;
          pairingCodeBox.textContent = `256-bitni ključ (prikazan le enkrat ob seznanitvi):\n${data.secret_key}\n\nPrstni odtis (SHA-256): ${data.fingerprint}\n\nKljuč varno shranite v datoteko na napravi (0600):\n./safeer-companion --secret-file /data/local/tmp/companion.key`;
          refreshShizukuStatus();
          showToast("🔑 Nov seznanitveni ključ ustvarjen");
        }
      } catch (e) {
        showToast(`❌ Napaka: ${e.message}`);
      }
    });
  }

  if (btnShizukuRotateKey) {
    btnShizukuRotateKey.addEventListener("click", async () => {
      if (!confirm("Ali ste prepričani, da želite rotirati ključ? Prejšnji ključ bo takoj neveljaven.")) return;
      try {
        const res = await fetch("/api/devices/shizuku_companion/rotate-key", {
          method: "POST",
          headers: getAuthHeaders(),
        });
        if (res.ok) {
          const data = await res.json();
          showToast(`🔄 Ključ rotiran: ${data.fingerprint}`);
          refreshShizukuStatus();
        }
      } catch (e) {
        showToast(`❌ Napaka pri rotaciji: ${e.message}`);
      }
    });
  }

  // Privileged actions (app.force_stop, settings.read, app.cache_maintenance)
  if (btnExecForceStop) {
    btnExecForceStop.addEventListener("click", () => {
      const pkg = selectForceStopPkg.value;
      apiAction("shizuku_companion", "app.force_stop", { package: pkg });
    });
  }

  if (btnExecReadSetting) {
    btnExecReadSetting.addEventListener("click", async () => {
      const key = inputSettingKey.value.trim();
      const ns = selectSettingNs.value;
      if (!key) return;
      try {
        const res = await fetch("/api/action", {
          method: "POST",
          headers: getAuthHeaders({ "Content-Type": "application/json" }),
          body: JSON.stringify({
            device_id: "shizuku_companion",
            action: "settings.read",
            params: { namespace: ns, key: key },
          }),
        });
        const data = await res.json();
        if (settingResultBox && settingResultText) {
          settingResultBox.style.display = "block";
          if (data.success && data.data) {
            settingResultText.textContent = `✅ ${ns}.${key} = "${data.data.value}"`;
          } else {
            settingResultText.textContent = `❌ Napaka: ${data.message}`;
          }
        }
      } catch (e) {
        showToast(`Napaka: ${e.message}`);
      }
    });
  }

  if (btnExecClearCache) {
    btnExecClearCache.addEventListener("click", () => {
      const pkg = inputCachePkg.value.trim();
      if (pkg) apiAction("shizuku_companion", "app.cache_maintenance", { package: pkg });
    });
  }

  // 9. OSVEŽEVALNIK IN SAMODEJNA ZANKA
  btnRefresh.addEventListener("click", () => {
    refreshDevices();
    showToast("Osvežujem podatke...");
  });

  // Začetni klic in periodično osveževanje
  refreshDevices();
  setInterval(refreshDevices, 4000);
});
