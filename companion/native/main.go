package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

var (
	secretKey = "safeer_companion_default_secret"
	rishPath  = "/data/local/tmp/rish"
)

var allowedPackages = map[string]bool{
	"com.example.safeerbrowser": true,
	"com.safeer.mobile.browser": true,
	"com.streamnexus.tv":        true,
	"com.streamnexus.mobile":    true,
	"com.streamnexus.assistant": true,
	"org.smarttube.stable":      true,
	"com.google.android.youtube.tv": true,
	"org.droidtv.playtv":        true,
	"org.droidtv.nettvbrowser":  true,
}

var protectedPackages = map[string]bool{
	"com.android.systemui":  true,
	"android":               true,
	"com.google.android.gms": true,
	"com.google.android.gsf": true,
	"com.android.settings":  true,
	"com.android.vending":   true,
}

var allowedSettingKeys = map[string]bool{
	"stay_on_while_plugged_in":     true,
	"animator_duration_scale":      true,
	"transition_animation_scale":  true,
	"window_animation_scale":      true,
	"adb_enabled":                 true,
	"device_name":                 true,
	"airplane_mode_on":            true,
	"bluetooth_on":                true,
	"wifi_on":                     true,
	"screen_off_timeout":          true,
	"development_settings_enabled": true,
}

type ReplayTracker struct {
	sync.Mutex
	seen map[string]float64
}

func (rt *ReplayTracker) CheckAndRecord(reqID, nonce string, ts float64) (bool, string) {
	rt.Lock()
	defer rt.Unlock()

	now := float64(time.Now().Unix())
	if math.Abs(now-ts) > 60.0 {
		return false, fmt.Sprintf("Zahteva časovno potekla (drift: %.2fs)", math.Abs(now-ts))
	}

	key := reqID + ":" + nonce
	if _, exists := rt.seen[key]; exists {
		return false, "Replay attack detected: duplicate request_id and nonce"
	}

	rt.seen[key] = ts
	// Očisti starejše od 120s
	for k, v := range rt.seen {
		if now-v > 120.0 {
			delete(rt.seen, k)
		}
	}
	return true, ""
}

var replayTracker = &ReplayTracker{seen: make(map[string]float64)}

type CompanionRequest struct {
	RequestID  string         `json:"request_id"`
	Timestamp  float64        `json:"timestamp"`
	Nonce      string         `json:"nonce"`
	Capability string         `json:"capability"`
	Params     map[string]any `json:"params"`
	Signature  string         `json:"signature"`
}

type CompanionResponse struct {
	RequestID    string         `json:"request_id"`
	Capability   string         `json:"capability"`
	Success      bool           `json:"success"`
	Data         map[string]any `json:"data,omitempty"`
	ErrorMessage *string        `json:"error_message,omitempty"`
}

func computeHMAC(secret, msg string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(msg))
	return hex.EncodeToString(h.Sum(nil))
}

func sendJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Preveri rish
	cmd := exec.Command(rishPath, "-c", "id")
	out, err := cmd.CombinedOutput()
	outStr := string(out)

	shizukuAvail := false
	permGranted := false
	status := "degraded"
	details := "Shizuku not responding"

	if err == nil && (strings.Contains(outStr, "uid=2000") || strings.Contains(outStr, "uid=0")) {
		shizukuAvail = true
		permGranted = true
		status = "ok"
		details = "Shizuku active via rish (UID 2000)"
	} else if strings.Contains(strings.ToLower(outStr), "permission") || strings.Contains(strings.ToLower(outStr), "denied") {
		shizukuAvail = true
		details = "Shizuku permission denied"
	}

	sendJSON(w, http.StatusOK, map[string]any{
		"status":                     status,
		"protocol_version":           "1.0",
		"companion_running":          true,
		"shizuku_available":          shizukuAvail,
		"shizuku_permission_granted": permGranted,
		"execution_mode":             "rish",
		"details":                    details,
	})
}

func handleCapability(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 65536))
	if err != nil || len(body) == 0 {
		sendJSON(w, http.StatusBadRequest, map[string]any{"success": false, "error_message": "Empty or invalid body"})
		return
	}

	var req CompanionRequest
	if err := json.Unmarshal(body, &req); err != nil {
		sendJSON(w, http.StatusBadRequest, map[string]any{"success": false, "error_message": "Invalid JSON"})
		return
	}

	// 1. Preveri HMAC
	canonParams, _ := json.Marshal(req.Params)
	canonStr := fmt.Sprintf("%s:%d:%s:%s:%s", req.RequestID, int64(req.Timestamp), req.Nonce, req.Capability, string(canonParams))
	expectedSig := computeHMAC(secretKey, canonStr)

	if !hmac.Equal([]byte(strings.ToLower(req.Signature)), []byte(strings.ToLower(expectedSig))) {
		errMsg := "Neveljaven ali manjkajoč HMAC-SHA256 podpis"
		sendJSON(w, http.StatusUnauthorized, CompanionResponse{
			RequestID:    req.RequestID,
			Capability:   req.Capability,
			Success:      false,
			ErrorMessage: &errMsg,
		})
		return
	}

	// 2. Anti-Replay
	okReplay, replayMsg := replayTracker.CheckAndRecord(req.RequestID, req.Nonce, req.Timestamp)
	if !okReplay {
		sendJSON(w, http.StatusBadRequest, CompanionResponse{
			RequestID:    req.RequestID,
			Capability:   req.Capability,
			Success:      false,
			ErrorMessage: &replayMsg,
		})
		return
	}

	// 3. Gate #2
	for _, forbidden := range []string{"exec", "cmd", "shell", "command", "argv", "su", "root", "script"} {
		if _, exists := req.Params[forbidden]; exists {
			errMsg := fmt.Sprintf("Varnostna kršitev (Gate #2): nedovoljeno polje '%s'", forbidden)
			sendJSON(w, http.StatusForbidden, CompanionResponse{
				RequestID:    req.RequestID,
				Capability:   req.Capability,
				Success:      false,
				ErrorMessage: &errMsg,
			})
			return
		}
	}

	switch req.Capability {
	case "settings.read":
		ns, _ := req.Params["namespace"].(string)
		key, _ := req.Params["key"].(string)
		ns = strings.ToLower(strings.TrimSpace(ns))
		key = strings.TrimSpace(key)

		if ns != "system" && ns != "secure" && ns != "global" {
			errMsg := fmt.Sprintf("Gate #2: nedovoljen namespace '%s'", ns)
			sendJSON(w, http.StatusForbidden, CompanionResponse{RequestID: req.RequestID, Capability: req.Capability, Success: false, ErrorMessage: &errMsg})
			return
		}
		if !allowedSettingKeys[key] {
			errMsg := fmt.Sprintf("Gate #2: ključ nastavitve '%s' ni na seznamu varnih dovoljenih nastavitev", key)
			sendJSON(w, http.StatusForbidden, CompanionResponse{RequestID: req.RequestID, Capability: req.Capability, Success: false, ErrorMessage: &errMsg})
			return
		}

		// Zagon settings get prek rish
		cmdStr := fmt.Sprintf("settings get %s %s", ns, key)
		cmd := exec.Command(rishPath, "-c", cmdStr)
		out, err := cmd.CombinedOutput()
		if err != nil {
			errMsg := fmt.Sprintf("Napaka pri branju nastavitve '%s.%s': %s", ns, key, string(out))
			sendJSON(w, http.StatusInternalServerError, CompanionResponse{RequestID: req.RequestID, Capability: req.Capability, Success: false, ErrorMessage: &errMsg})
			return
		}

		rawVal := strings.TrimSpace(string(out))
		var val any = rawVal
		if rawVal == "null" || rawVal == "" {
			val = nil
		}
		sendJSON(w, http.StatusOK, CompanionResponse{
			RequestID:  req.RequestID,
			Capability: req.Capability,
			Success:    true,
			Data: map[string]any{
				"namespace": ns,
				"key":       key,
				"value":     val,
			},
		})

	case "app.force_stop":
		pkg, _ := req.Params["package"].(string)
		pkg = strings.TrimSpace(pkg)

		if protectedPackages[pkg] || strings.HasPrefix(pkg, "com.android.") || pkg == "android" {
			errMsg := fmt.Sprintf("Gate #2 zavrnil zaustavitev zaščitenega sistemskega paketa '%s'", pkg)
			sendJSON(w, http.StatusForbidden, CompanionResponse{RequestID: req.RequestID, Capability: req.Capability, Success: false, ErrorMessage: &errMsg})
			return
		}
		if !allowedPackages[pkg] {
			errMsg := fmt.Sprintf("Gate #2 zavrnil nepooblaščen paket '%s'", pkg)
			sendJSON(w, http.StatusForbidden, CompanionResponse{RequestID: req.RequestID, Capability: req.Capability, Success: false, ErrorMessage: &errMsg})
			return
		}

		cmdStr := fmt.Sprintf("am force-stop %s", pkg)
		cmd := exec.Command(rishPath, "-c", cmdStr)
		out, err := cmd.CombinedOutput()
		if err != nil {
			errMsg := fmt.Sprintf("Napaka pri zaustavitvi aplikacije '%s': %s", pkg, string(out))
			sendJSON(w, http.StatusInternalServerError, CompanionResponse{RequestID: req.RequestID, Capability: req.Capability, Success: false, ErrorMessage: &errMsg})
			return
		}

		sendJSON(w, http.StatusOK, CompanionResponse{
			RequestID:  req.RequestID,
			Capability: req.Capability,
			Success:    true,
			Data:       map[string]any{"package": pkg},
		})

	case "app.cache_maintenance":
		pkg, _ := req.Params["package"].(string)
		pkg = strings.TrimSpace(pkg)

		if !allowedPackages[pkg] {
			errMsg := fmt.Sprintf("Gate #2: paket '%s' ni na seznamu dovoljenih paketov za vzdrževanje", pkg)
			sendJSON(w, http.StatusForbidden, CompanionResponse{RequestID: req.RequestID, Capability: req.Capability, Success: false, ErrorMessage: &errMsg})
			return
		}

		cmdStr := fmt.Sprintf("pm trim-caches 4096M && rm -rf /sdcard/Android/data/%s/cache/*", pkg)
		cmd := exec.Command(rishPath, "-c", cmdStr)
		out, err := cmd.CombinedOutput()
		if err != nil {
			errMsg := fmt.Sprintf("Napaka pri vzdrževanju predpomnilnika za '%s': %s", pkg, string(out))
			sendJSON(w, http.StatusInternalServerError, CompanionResponse{RequestID: req.RequestID, Capability: req.Capability, Success: false, ErrorMessage: &errMsg})
			return
		}

		sendJSON(w, http.StatusOK, CompanionResponse{
			RequestID:  req.RequestID,
			Capability: req.Capability,
			Success:    true,
			Data: map[string]any{
				"package": pkg,
				"trimmed": true,
			},
		})

	default:
		errMsg := fmt.Sprintf("Gate #2: neznana ali nepodprta zmožnost: '%s'", req.Capability)
		sendJSON(w, http.StatusBadRequest, CompanionResponse{RequestID: req.RequestID, Capability: req.Capability, Success: false, ErrorMessage: &errMsg})
	}
}

func main() {
	port := flag.Int("port", 8995, "Vrata poslušanja")
	host := flag.String("host", "0.0.0.0", "Host")
	flag.StringVar(&secretKey, "secret", "safeer_companion_default_secret", "HMAC skrivni ključ")
	flag.StringVar(&rishPath, "rish-path", "/data/local/tmp/rish", "Pot do rish")
	flag.Parse()

	http.HandleFunc("/api/companion/health", handleHealth)
	http.HandleFunc("/api/companion/capability", handleCapability)

	addr := fmt.Sprintf("%s:%d", *host, *port)
	fmt.Printf("Safeer Companion daemon posluša na %s...\n", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		fmt.Fprintf(os.Stderr, "Napaka strežnika: %v\n", err)
		os.Exit(1)
	}
}
