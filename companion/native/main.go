package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	CompanionVersion = "0.9.0"
	ProtocolVersion  = "1.1"
)

var startTime = time.Now()

var (
	secretKey        = ""
	rishPath         = "/data/local/tmp/rish"
	activeSecretFile = ""
	tlsFingerprint   = ""

	pairMutex    sync.Mutex
	pairingPIN   = ""
	pinExpiresAt time.Time

	validPkgRegex = regexp.MustCompile(`^[a-zA-Z0-9_\.]+$`)
	validKeyRegex = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
	validNsRegex  = regexp.MustCompile(`^[a-z]+$`)
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

func derivePairingKey(pin, clientNonce, serverNonce, info string) string {
	ikm := []byte(strings.TrimSpace(pin))
	salt := []byte(fmt.Sprintf("%s:%s", clientNonce, serverNonce))
	infoBytes := []byte(info)

	// HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
	hPrk := hmac.New(sha256.New, salt)
	hPrk.Write(ikm)
	prk := hPrk.Sum(nil)

	// HKDF-Expand: T(1) = HMAC-Hash(PRK, info || 0x01)
	hT1 := hmac.New(sha256.New, prk)
	hT1.Write(infoBytes)
	hT1.Write([]byte{0x01})
	t1 := hT1.Sum(nil)

	return hex.EncodeToString(t1[:32])
}

type PairingHandshakeRequest struct {
	Pin         string `json:"pin"`
	ClientNonce string `json:"client_nonce"`
}

type PairingHandshakeResponse struct {
	Success        bool   `json:"success"`
	ServerNonce    string `json:"server_nonce,omitempty"`
	TLSFingerprint string `json:"tls_fingerprint,omitempty"`
	ErrorMessage   string `json:"error_message,omitempty"`
}

type PairingInitRequest struct {
	ClientNonce string `json:"client_nonce"`
}

type PairingInitResponse struct {
	Success        bool   `json:"success"`
	ServerNonce    string `json:"server_nonce,omitempty"`
	TLSFingerprint string `json:"tls_fingerprint,omitempty"`
	ErrorMessage   string `json:"error_message,omitempty"`
}

type PairingConfirmRequest struct {
	ClientNonce string `json:"client_nonce"`
	ClientAuth  string `json:"client_auth"`
}

type PairingConfirmResponse struct {
	Success      bool   `json:"success"`
	ServerAuth   string `json:"server_auth,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
}

type pairSession struct {
	serverNonce string
	expiresAt   time.Time
}

var (
	failedPairAttempts = 0
	maxPairAttempts    = 3
	activePairSessions = make(map[string]pairSession)
)

func computePairingTranscript(clientNonce, serverNonce, certFingerprint string) string {
	fpClean := strings.ToLower(strings.TrimSpace(certFingerprint))
	return fmt.Sprintf("safeer-bootstrap-v0.8.1:%s:%s:%s", clientNonce, serverNonce, fpClean)
}

func derivePairingAuthKey(pin, clientNonce, serverNonce string) []byte {
	ikm := []byte(strings.TrimSpace(pin))
	salt := []byte(fmt.Sprintf("%s:%s", clientNonce, serverNonce))
	info := []byte("safeer-pake-auth-v0.8.1")

	hPrk := hmac.New(sha256.New, salt)
	hPrk.Write(ikm)
	prk := hPrk.Sum(nil)

	hT1 := hmac.New(sha256.New, prk)
	hT1.Write(info)
	hT1.Write([]byte{0x01})
	return hT1.Sum(nil)[:32]
}

func computeTranscriptAuth(authKey []byte, transcript, role string) string {
	msg := []byte(fmt.Sprintf("%s:%s", transcript, role))
	h := hmac.New(sha256.New, authKey)
	h.Write(msg)
	return hex.EncodeToString(h.Sum(nil))
}

func deriveFinalSharedKey(authKey []byte, transcript string) string {
	info := []byte("safeer-companion-v0.8.1-session")
	hPrk := hmac.New(sha256.New, []byte(transcript))
	hPrk.Write(authKey)
	prk := hPrk.Sum(nil)

	hT1 := hmac.New(sha256.New, prk)
	hT1.Write(info)
	hT1.Write([]byte{0x01})
	return hex.EncodeToString(hT1.Sum(nil)[:32])
}

func handlePairInit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 65536))
	if err != nil || len(body) == 0 {
		sendJSON(w, http.StatusBadRequest, PairingInitResponse{Success: false, ErrorMessage: "Empty body"})
		return
	}
	var req PairingInitRequest
	if err := json.Unmarshal(body, &req); err != nil {
		sendJSON(w, http.StatusBadRequest, PairingInitResponse{Success: false, ErrorMessage: "Invalid JSON"})
		return
	}

	pairMutex.Lock()
	defer pairMutex.Unlock()

	now := time.Now()
	if pairingPIN == "" || now.After(pinExpiresAt) {
		sendJSON(w, http.StatusForbidden, PairingInitResponse{
			Success:      false,
			ErrorMessage: "Fail-closed: Seznanitveni način ni aktiven ali pa je PIN potekel.",
		})
		return
	}

	if failedPairAttempts >= maxPairAttempts {
		sendJSON(w, http.StatusForbidden, PairingInitResponse{
			Success:      false,
			ErrorMessage: "Fail-closed: Preseženo maksimalno število poskusov (3/3). Seznanitev zaklenjena.",
		})
		return
	}

	nonceBytes := make([]byte, 16)
	_, _ = rand.Read(nonceBytes)
	sNonce := hex.EncodeToString(nonceBytes)

	activePairSessions[req.ClientNonce] = pairSession{
		serverNonce: sNonce,
		expiresAt:   now.Add(60 * time.Second),
	}

	sendJSON(w, http.StatusOK, PairingInitResponse{
		Success:        true,
		ServerNonce:    sNonce,
		TLSFingerprint: tlsFingerprint,
	})
}

func handlePairConfirm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 65536))
	if err != nil || len(body) == 0 {
		sendJSON(w, http.StatusBadRequest, PairingConfirmResponse{Success: false, ErrorMessage: "Empty body"})
		return
	}
	var req PairingConfirmRequest
	if err := json.Unmarshal(body, &req); err != nil {
		sendJSON(w, http.StatusBadRequest, PairingConfirmResponse{Success: false, ErrorMessage: "Invalid JSON"})
		return
	}

	pairMutex.Lock()
	defer pairMutex.Unlock()

	now := time.Now()
	if pairingPIN == "" || now.After(pinExpiresAt) {
		sendJSON(w, http.StatusForbidden, PairingConfirmResponse{
			Success:      false,
			ErrorMessage: "Fail-closed: Seznanitveni način ni aktiven ali pa je PIN potekel.",
		})
		return
	}

	if failedPairAttempts >= maxPairAttempts {
		sendJSON(w, http.StatusForbidden, PairingConfirmResponse{
			Success:      false,
			ErrorMessage: "Fail-closed: Preseženo maksimalno število poskusov (3/3). Seznanitev zaklenjena.",
		})
		return
	}

	sess, ok := activePairSessions[req.ClientNonce]
	if !ok || now.After(sess.expiresAt) {
		sendJSON(w, http.StatusBadRequest, PairingConfirmResponse{
			Success:      false,
			ErrorMessage: "Fail-closed: Seja seznanitve ni bila najdena ali je potekla.",
		})
		return
	}

	transcript := computePairingTranscript(req.ClientNonce, sess.serverNonce, tlsFingerprint)
	authKey := derivePairingAuthKey(pairingPIN, req.ClientNonce, sess.serverNonce)
	expectedClientAuth := computeTranscriptAuth(authKey, transcript, "client")

	if !hmac.Equal([]byte(strings.ToLower(req.ClientAuth)), []byte(strings.ToLower(expectedClientAuth))) {
		failedPairAttempts++
		attemptsLeft := maxPairAttempts - failedPairAttempts
		if failedPairAttempts >= maxPairAttempts {
			pairingPIN = ""
			activePairSessions = make(map[string]pairSession)
			sendJSON(w, http.StatusForbidden, PairingConfirmResponse{
				Success:      false,
				ErrorMessage: "Fail-closed: Preseženo število poskusov (3/3). PIN preklican.",
			})
			return
		}
		sendJSON(w, http.StatusForbidden, PairingConfirmResponse{
			Success:      false,
			ErrorMessage: fmt.Sprintf("Fail-closed: Napačna avtentikacija transkripta (preostali poskusi: %d)", attemptsLeft),
		})
		return
	}

	serverAuth := computeTranscriptAuth(authKey, transcript, "server")
	finalKey := deriveFinalSharedKey(authKey, transcript)
	secretKey = finalKey

	if activeSecretFile != "" {
		_ = os.WriteFile(activeSecretFile, []byte(finalKey), 0600)
	}

	pairingPIN = ""
	activePairSessions = make(map[string]pairSession)

	sendJSON(w, http.StatusOK, PairingConfirmResponse{
		Success:    true,
		ServerAuth: serverAuth,
	})
}

func sendJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func getOrCreateTLSCertificate(certPath, keyPath string) (tls.Certificate, string, error) {
	if certPath != "" && keyPath != "" {
		if _, err := os.Stat(certPath); err == nil {
			if _, err := os.Stat(keyPath); err == nil {
				cert, err := tls.LoadX509KeyPair(certPath, keyPath)
				if err == nil && len(cert.Certificate) > 0 {
					h := sha256.Sum256(cert.Certificate[0])
					return cert, hex.EncodeToString(h[:]), nil
				}
			}
		}
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("ecdsa generate: %w", err)
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Safeer Security"},
			CommonName:   "SafeerCompanion",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("create cert: %w", err)
	}

	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	privBytes, _ := x509.MarshalECPrivateKey(priv)
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	if certPath != "" && keyPath != "" {
		_ = os.MkdirAll(filepath.Dir(certPath), 0700)
		_ = os.MkdirAll(filepath.Dir(keyPath), 0700)
		_ = os.WriteFile(certPath, certPem, 0644)
		_ = os.WriteFile(keyPath, keyPem, 0600)
	}

	h := sha256.Sum256(derBytes)
	fp := hex.EncodeToString(h[:])

	cert, err := tls.X509KeyPair(certPem, keyPem)
	return cert, fp, err
}

func handlePairHandshake(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 65536))
	if err != nil || len(body) == 0 {
		sendJSON(w, http.StatusBadRequest, PairingHandshakeResponse{Success: false, ErrorMessage: "Empty or invalid body"})
		return
	}

	var req PairingHandshakeRequest
	if err := json.Unmarshal(body, &req); err != nil {
		sendJSON(w, http.StatusBadRequest, PairingHandshakeResponse{Success: false, ErrorMessage: "Invalid JSON"})
		return
	}

	pairMutex.Lock()
	defer pairMutex.Unlock()

	now := time.Now()
	if pairingPIN == "" || now.After(pinExpiresAt) {
		sendJSON(w, http.StatusForbidden, PairingHandshakeResponse{
			Success:      false,
			ErrorMessage: "Fail-closed: Seznanitveni način ni aktiven ali pa je PIN potekel.",
		})
		return
	}

	if !hmac.Equal([]byte(strings.TrimSpace(req.Pin)), []byte(strings.TrimSpace(pairingPIN))) {
		sendJSON(w, http.StatusForbidden, PairingHandshakeResponse{
			Success:      false,
			ErrorMessage: "Fail-closed: Napačen PIN za seznanitev.",
		})
		return
	}

	nonceBytes := make([]byte, 16)
	_, _ = rand.Read(nonceBytes)
	serverNonce := hex.EncodeToString(nonceBytes)

	derived := derivePairingKey(req.Pin, req.ClientNonce, serverNonce, "safeer-companion-v0.8")
	secretKey = derived

	if activeSecretFile != "" {
		_ = os.WriteFile(activeSecretFile, []byte(derived), 0600)
	}

	// Takoj uniči PIN po enkratni uporabi
	pairingPIN = ""
	pinExpiresAt = time.Time{}

	sendJSON(w, http.StatusOK, PairingHandshakeResponse{
		Success:        true,
		ServerNonce:    serverNonce,
		TLSFingerprint: tlsFingerprint,
	})
}

type UpdateRequest struct {
	BinaryB64 string  `json:"binary_b64"`
	SHA256    string  `json:"sha256"`
	Restart   bool    `json:"restart"`
	Signature string  `json:"signature"`
	Timestamp float64 `json:"timestamp"`
	Nonce     string  `json:"nonce"`
}

type UpdateResponse struct {
	Success      bool   `json:"success"`
	OldVersion   string `json:"old_version,omitempty"`
	NewVersion   string `json:"new_version,omitempty"`
	Message      string `json:"message"`
	ErrorMessage string `json:"error_message,omitempty"`
}

func probeShizuku() (avail bool, granted bool, status string, details string, state string) {
	cmd := exec.Command(rishPath, "-c", "id")
	out, err := cmd.CombinedOutput()
	outStr := string(out)

	if err == nil && (strings.Contains(outStr, "uid=2000") || strings.Contains(outStr, "uid=0")) {
		return true, true, "ok", "Shizuku active via rish (UID 2000)", "ready"
	}
	if strings.Contains(strings.ToLower(outStr), "permission") || strings.Contains(strings.ToLower(outStr), "denied") {
		return true, false, "degraded", "Shizuku permission denied", "permission_denied"
	}
	return false, false, "degraded", fmt.Sprintf("Shizuku not responding: %s", strings.TrimSpace(outStr)), "waiting_for_shizuku"
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	avail, granted, status, details, state := probeShizuku()

	respMap := map[string]any{
		"status":                     status,
		"version":                    CompanionVersion,
		"protocol_version":           ProtocolVersion,
		"companion_running":          true,
		"shizuku_available":          avail,
		"shizuku_permission_granted": granted,
		"shizuku_state":              state,
		"execution_mode":             "rish",
		"details":                    details,
		"uptime_seconds":             math.Round(time.Since(startTime).Seconds()*10) / 10,
		"pid":                        os.Getpid(),
	}

	if tlsFingerprint != "" {
		respMap["tls_enabled"] = true
		respMap["tls_fingerprint"] = tlsFingerprint
	}

	pairMutex.Lock()
	if pairingPIN != "" && time.Now().Before(pinExpiresAt) {
		respMap["pairing_mode"] = true
	}
	pairMutex.Unlock()

	sendJSON(w, http.StatusOK, respMap)
}

func handleLifecycle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	avail, granted, status, details, state := probeShizuku()

	pairActive := false
	pairMutex.Lock()
	if pairingPIN != "" && time.Now().Before(pinExpiresAt) {
		pairActive = true
	}
	pairMutex.Unlock()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	resp := map[string]any{
		"status":                     status,
		"version":                    CompanionVersion,
		"protocol_version":           ProtocolVersion,
		"companion_running":          true,
		"uptime_seconds":             math.Round(time.Since(startTime).Seconds()*10) / 10,
		"pid":                        os.Getpid(),
		"shizuku_available":          avail,
		"shizuku_permission_granted": granted,
		"shizuku_state":              state,
		"details":                    details,
		"execution_mode":             "rish",
		"tls_enabled":                tlsFingerprint != "",
		"tls_fingerprint":            tlsFingerprint,
		"pairing_active":             pairActive,
		"memory_alloc_kb":            m.Alloc / 1024,
		"supported_capabilities": []string{
			"settings.read",
			"app.force_stop",
			"app.cache_maintenance",
		},
	}
	sendJSON(w, http.StatusOK, resp)
}

func handleUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if len(secretKey) < 32 {
		sendJSON(w, http.StatusServiceUnavailable, UpdateResponse{
			Success:      false,
			ErrorMessage: "Fail-closed: Companion skrivni ključ ni konfiguriran (Pairing required)",
		})
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 32*1024*1024))
	if err != nil || len(body) == 0 {
		sendJSON(w, http.StatusBadRequest, UpdateResponse{Success: false, ErrorMessage: "Empty or invalid body"})
		return
	}

	var req UpdateRequest
	if err := json.Unmarshal(body, &req); err != nil {
		sendJSON(w, http.StatusBadRequest, UpdateResponse{Success: false, ErrorMessage: "Invalid JSON"})
		return
	}

	// 1. HMAC avtentikacija
	canonStr := fmt.Sprintf("update:%d:%s:%s", int64(req.Timestamp), req.Nonce, strings.ToLower(req.SHA256))
	expectedSig := computeHMAC(secretKey, canonStr)

	if !hmac.Equal([]byte(strings.ToLower(req.Signature)), []byte(strings.ToLower(expectedSig))) {
		sendJSON(w, http.StatusUnauthorized, UpdateResponse{
			Success:      false,
			ErrorMessage: "Fail-closed: Neveljaven HMAC podpis posodobitve",
		})
		return
	}

	// 2. Anti-Replay
	okReplay, replayMsg := replayTracker.CheckAndRecord("update", req.Nonce, req.Timestamp)
	if !okReplay {
		sendJSON(w, http.StatusBadRequest, UpdateResponse{
			Success:      false,
			ErrorMessage: replayMsg,
		})
		return
	}

	// 3. Dekodiranje in SHA-256 verifikacija
	binBytes, err := base64.StdEncoding.DecodeString(req.BinaryB64)
	if err != nil || len(binBytes) == 0 {
		sendJSON(w, http.StatusBadRequest, UpdateResponse{Success: false, ErrorMessage: "Invalid base64 binary payload"})
		return
	}

	h := sha256.Sum256(binBytes)
	actualSHA := hex.EncodeToString(h[:])
	if !strings.EqualFold(actualSHA, strings.TrimSpace(req.SHA256)) {
		sendJSON(w, http.StatusBadRequest, UpdateResponse{
			Success:      false,
			ErrorMessage: fmt.Sprintf("Fail-closed: SHA-256 hash mismatch! Expected %s, got %s", req.SHA256, actualSHA),
		})
		return
	}

	// 4. Preveri trenutno pot do binarne datoteke
	execPath, err := os.Executable()
	if err != nil {
		sendJSON(w, http.StatusInternalServerError, UpdateResponse{Success: false, ErrorMessage: "Could not determine executable path"})
		return
	}
	execPath, _ = filepath.EvalSymlinks(execPath)

	newPath := execPath + ".new"
	bakPath := execPath + ".bak"

	// 5. Zapiši z 0700
	if err := os.WriteFile(newPath, binBytes, 0700); err != nil {
		sendJSON(w, http.StatusInternalServerError, UpdateResponse{Success: false, ErrorMessage: fmt.Sprintf("Write failed: %v", err)})
		return
	}

	// 6. Testiraj veljavnost novega binarnega programa
	testCmd := exec.Command(newPath, "-version")
	testOut, err := testCmd.CombinedOutput()
	if err != nil {
		_ = os.Remove(newPath)
		sendJSON(w, http.StatusBadRequest, UpdateResponse{
			Success:      false,
			ErrorMessage: fmt.Sprintf("Fail-closed: Nova binarna datoteka ni prestala zagonskega testa (-version): %v (%s)", err, string(testOut)),
		})
		return
	}
	newVerStr := strings.TrimSpace(string(testOut))

	// 7. Atomarna zamenjava
	_ = os.Remove(bakPath)
	_ = os.Rename(execPath, bakPath)
	if err := os.Rename(newPath, execPath); err != nil {
		_ = os.Rename(bakPath, execPath) // Rollback
		sendJSON(w, http.StatusInternalServerError, UpdateResponse{Success: false, ErrorMessage: fmt.Sprintf("Atomic rename failed: %v", err)})
		return
	}

	sendJSON(w, http.StatusOK, UpdateResponse{
		Success:    true,
		OldVersion: CompanionVersion,
		NewVersion: newVerStr,
		Message:    "Posodobitev uspešno nameščena z atomarno zamenjavo.",
	})

	if req.Restart {
		go func() {
			time.Sleep(300 * time.Millisecond)
			cmd := exec.Command(execPath, os.Args[1:]...)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			_ = cmd.Start()
			os.Exit(0)
		}()
	}
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

	// 0. Preveri ali je nastavljen veljaven skrivni ključ (Fail-Closed)
	if len(secretKey) < 32 {
		errMsg := "Fail-closed: Companion skrivni ključ ni konfiguriran ali ima manj kot 256 bitov (Pairing required)"
		sendJSON(w, http.StatusServiceUnavailable, CompanionResponse{
			RequestID:    req.RequestID,
			Capability:   req.Capability,
			Success:      false,
			ErrorMessage: &errMsg,
		})
		return
	}

	// 0b. Preveri Shizuku pravice (Fail-Closed ob Shizuku izpadu ali manjkajočih pravicah)
	_, granted, _, details, state := probeShizuku()
	if !granted {
		errMsg := fmt.Sprintf("Fail-closed: Shizuku storitev ni na voljo ali pa manjkajo pravice (stanje: %s, podrobnosti: %s)", state, details)
		sendJSON(w, http.StatusServiceUnavailable, CompanionResponse{
			RequestID:    req.RequestID,
			Capability:   req.Capability,
			Success:      false,
			ErrorMessage: &errMsg,
		})
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
		if !validNsRegex.MatchString(ns) || !validKeyRegex.MatchString(key) {
			errMsg := "Gate #2: neveljavni znaki v parametrih nastavitve (injection preprečen)"
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

		if !validPkgRegex.MatchString(pkg) {
			errMsg := "Gate #2: neveljavni znaki v imenu paketa (injection preprečen)"
			sendJSON(w, http.StatusForbidden, CompanionResponse{RequestID: req.RequestID, Capability: req.Capability, Success: false, ErrorMessage: &errMsg})
			return
		}
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

		if !validPkgRegex.MatchString(pkg) {
			errMsg := "Gate #2: neveljavni znaki v imenu paketa (injection preprečen)"
			sendJSON(w, http.StatusForbidden, CompanionResponse{RequestID: req.RequestID, Capability: req.Capability, Success: false, ErrorMessage: &errMsg})
			return
		}
		if !allowedPackages[pkg] {
			errMsg := fmt.Sprintf("Gate #2: paket '%s' ni na seznamu dovoljenih paketov za vzdrževanje", pkg)
			sendJSON(w, http.StatusForbidden, CompanionResponse{RequestID: req.RequestID, Capability: req.Capability, Success: false, ErrorMessage: &errMsg})
			return
		}

		cmdStr := fmt.Sprintf("rm -rf /sdcard/Android/data/%s/cache/*", pkg)
		cmd := exec.Command(rishPath, "-c", cmdStr)
		out, err := cmd.CombinedOutput()
		if err != nil {
			errMsg := fmt.Sprintf("Napaka pri čiščenju predpomnilnika za '%s': %s", pkg, string(out))
			sendJSON(w, http.StatusInternalServerError, CompanionResponse{RequestID: req.RequestID, Capability: req.Capability, Success: false, ErrorMessage: &errMsg})
			return
		}

		sendJSON(w, http.StatusOK, CompanionResponse{
			RequestID:  req.RequestID,
			Capability: req.Capability,
			Success:    true,
			Data: map[string]any{
				"package":       pkg,
				"cache_cleared": true,
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
	secretFile := flag.String("secret-file", "", "Pot do varovane datoteke s ključem (0600)")
	flag.StringVar(&secretKey, "secret", "", "HMAC skrivni ključ (vsaj 256-bit / 32 znakov)")
	flag.StringVar(&rishPath, "rish-path", "/data/local/tmp/rish", "Pot do rish")
	enableTLS := flag.Bool("tls", false, "Omogoči TLS šifrirano povezavo")
	certFile := flag.String("cert", "/data/local/tmp/companion.crt", "Pot do TLS certifikata")
	keyFile := flag.String("key", "/data/local/tmp/companion.key", "Pot do TLS ključa (0600)")
	pairMode := flag.Bool("pair", false, "Aktiviraj seznanitveni način (generira 6-mestni PIN)")
	showVersion := flag.Bool("version", false, "Izpiši verzijo in končaj")
	flag.Parse()

	if *showVersion {
		fmt.Printf("Safeer Companion v%s (protocol %s)\n", CompanionVersion, ProtocolVersion)
		os.Exit(0)
	}

	if *secretFile != "" {
		activeSecretFile = *secretFile
		data, err := os.ReadFile(*secretFile)
		if err == nil {
			secretKey = strings.TrimSpace(string(data))
		}
	}

	if *pairMode {
		pairMutex.Lock()
		n, _ := rand.Int(rand.Reader, big.NewInt(900000))
		pairingPIN = fmt.Sprintf("%06d", n.Int64()+100000)
		pinExpiresAt = time.Now().Add(180 * time.Second)
		pairMutex.Unlock()

		fmt.Println("==========================================================")
		fmt.Println("  SAFEER COMPANION V0.9 — NAČIN ZA SEZNANITEV (PAIRING)")
		fmt.Printf("  PIN ZA SEZNANITEV: %s\n", pairingPIN)
		fmt.Println("  Veljavnost: 180 sekund (enkratna uporaba, max 3 poskusi)")
		fmt.Println("==========================================================")
	}

	if !*pairMode && len(secretKey) < 32 {
		fmt.Printf("OPOZORILO (Fail-Closed): Skrivni ključ ni konfiguriran ali ima manj kot 32 znakov (256 bitov). Privilegirani klici bodo zavrnjeni.\n")
	}

	http.HandleFunc("/api/companion/health", handleHealth)
	http.HandleFunc("/api/companion/lifecycle", handleLifecycle)
	http.HandleFunc("/api/companion/update", handleUpdate)
	http.HandleFunc("/api/companion/capability", handleCapability)
	http.HandleFunc("/api/companion/pair/handshake", handlePairHandshake)
	http.HandleFunc("/api/companion/pair/init", handlePairInit)
	http.HandleFunc("/api/companion/pair/confirm", handlePairConfirm)

	addr := fmt.Sprintf("%s:%d", *host, *port)

	if *enableTLS {
		tlsCert, fp, err := getOrCreateTLSCertificate(*certFile, *keyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Napaka pri inicializaciji TLS certifikata: %v\n", err)
			os.Exit(1)
		}
		tlsFingerprint = fp
		fmt.Printf("TLS Certifikat SHA-256 Fingerprint: %s\n", tlsFingerprint)

		server := &http.Server{
			Addr: addr,
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{tlsCert},
			},
		}
		fmt.Printf("Safeer Companion TLS daemon posluša na https://%s...\n", addr)
		if err := server.ListenAndServeTLS("", ""); err != nil {
			fmt.Fprintf(os.Stderr, "Napaka TLS strežnika: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Printf("Safeer Companion daemon posluša na http://%s...\n", addr)
		if err := http.ListenAndServe(addr, nil); err != nil {
			fmt.Fprintf(os.Stderr, "Napaka strežnika: %v\n", err)
			os.Exit(1)
		}
	}
}

