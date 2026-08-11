package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/dtls/v3"
	"golang.org/x/crypto/curve25519"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
)

var bufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 1600)
		return &b
	},
}

func getBuf() *[]byte  { return bufPool.Get().(*[]byte) }
func putBuf(b *[]byte) { bufPool.Put(b) }

var (
	totalBytesFromClient int64
	totalBytesToClient   int64
	activeConns          int32
	activeV2Conns        int32
	activeLegacyConns    int32
	totalConns           int64
	admittedConns        int64
	successfulHandshakes int64
	failedHandshakes     int64
	rejectedConns        int64
	natType              string = "Инициализация..."
	serverStartTime      time.Time
)

func statsLoop(ctx context.Context, configDir string, lifecycleRegistry *relayLifecycleRegistry) {
	serverStartTime = time.Now()
	statsFile := filepath.Join(configDir, "server.log")

	// интервал с 10 секунд на 1 минуту, чтобы снизить нагрузку на диск и процессор
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fromC := atomic.LoadInt64(&totalBytesFromClient)
			toC := atomic.LoadInt64(&totalBytesToClient)
			active := atomic.LoadInt32(&activeConns)
			activeV2 := atomic.LoadInt32(&activeV2Conns)
			activeLegacy := atomic.LoadInt32(&activeLegacyConns)
			total := atomic.LoadInt64(&totalConns)
			admitted := atomic.LoadInt64(&admittedConns)
			handshakes := atomic.LoadInt64(&successfulHandshakes)
			handshakeFailures := atomic.LoadInt64(&failedHandshakes)
			rejected := atomic.LoadInt64(&rejectedConns)
			lifecycle := lifecycleRegistry.Stats()
			uptime := time.Since(serverStartTime)

			dbMutex.Lock()
			numPasswords := len(db.Passwords)
			numDevices := len(db.Devices)
			dbMutex.Unlock()

			uptimeStr := formatUptime(uptime)
			downGB := float64(toC) / (1024 * 1024 * 1024)
			upGB := float64(fromC) / (1024 * 1024 * 1024)

			log.Printf("[СТАТ] Активных: %d (v2: %d, legacy: %d) | Relay за uptime: %d | Допущено к DTLS: %d | DTLS успешно: %d | Ошибок DTLS: %d | Отклонено до DTLS: %d | Заменено v2: %d | Отклонено stale v2: %d | Вытеснено legacy: %d | Uptime: %s | Получено: %.2f GB | Отправлено: %.2f GB | Паролей: %d | Устройств: %d",
				active, activeV2, activeLegacy, total, admitted, handshakes, handshakeFailures, rejected, lifecycle.V2Replaced, lifecycle.V2StaleDenied,
				lifecycle.LegacyEvicted, uptimeStr, downGB, upGB, numPasswords, numDevices)

			statsJSON, err := json.Marshal(map[string]interface{}{
				"active":                         active,
				"active_v2":                      activeV2,
				"active_legacy":                  activeLegacy,
				"total":                          total,
				"accepted_since_start":           total,
				"relay_sessions_since_start":     total,
				"admitted_since_start":           admitted,
				"dtls_handshakes_since_start":    handshakes,
				"dtls_handshake_failures":        handshakeFailures,
				"rejected":                       rejected,
				"admission_rejected_since_start": rejected,
				"v2_replaced":                    lifecycle.V2Replaced,
				"v2_stale_denied":                lifecycle.V2StaleDenied,
				"legacy_evicted":                 lifecycle.LegacyEvicted,
				"nat":                            natType,
				"uptime":                         uptimeStr,
				"down_gb":                        fmt.Sprintf("%.2f", downGB),
				"up_gb":                          fmt.Sprintf("%.2f", upGB),
				"passwords":                      numPasswords,
				"devices":                        numDevices,
				"timestamp":                      time.Now().Unix(),
			})
			if err != nil {
				log.Printf("[СТАТ] Не удалось сериализовать статистику: %v", err)
				continue
			}
			if err := os.WriteFile(statsFile, statsJSON, 0644); err != nil {
				log.Printf("[СТАТ] Не удалось записать %s: %v", statsFile, err)
			}
		}
	}
}

func formatUptime(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	if days > 0 {
		return fmt.Sprintf("%dд %dч %dм", days, hours, mins)
	}
	if hours > 0 {
		return fmt.Sprintf("%dч %dм", hours, mins)
	}
	return fmt.Sprintf("%dм", mins)
}

func runCmd(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func runCmdSilent(name string, args ...string) string {
	out, _ := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out))
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func defaultInterfaceFromRoutes(routes string) string {
	for _, line := range strings.Split(routes, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "default" {
			continue
		}
		for i := 1; i+1 < len(fields); i++ {
			if fields[i] == "dev" {
				return fields[i+1]
			}
		}
	}
	return ""
}

func getDefaultInterface() (string, error) {
	out, err := runCmd("ip", "route", "show", "default")
	if err != nil {
		return "", fmt.Errorf("read default route: %w: %s", err, out)
	}
	iface := defaultInterfaceFromRoutes(out)
	if iface == "" {
		return "", errors.New("default route has no interface")
	}
	if linkOut, err := runCmd("ip", "link", "show", "dev", iface); err != nil {
		return "", fmt.Errorf("validate external interface %s: %w: %s", iface, err, linkOut)
	}
	return iface, nil
}

type wgKeys struct {
	serverPrivate, serverPublic string
}

func b64ToHex(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	if len(b) != 32 {
		return "", fmt.Errorf("key length %d != 32", len(b))
	}
	return hex.EncodeToString(b), nil
}

func generateKeyPair() (privB64, pubB64 string, err error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return "", "", err
	}
	priv[0] &= 248
	priv[31] = (priv[31] & 127) | 64
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(priv[:]),
		base64.StdEncoding.EncodeToString(pub), nil
}

func validateKeyPair(privateKey, publicKey string) error {
	privateRaw, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil || len(privateRaw) != 32 {
		return errors.New("invalid private key")
	}
	publicRaw, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil || len(publicRaw) != 32 {
		return errors.New("invalid public key")
	}
	derivedPublic, err := curve25519.X25519(privateRaw, curve25519.Basepoint)
	if err != nil {
		return fmt.Errorf("derive public key: %w", err)
	}
	if !bytes.Equal(derivedPublic, publicRaw) {
		return errors.New("public key does not match private key")
	}
	return nil
}

func validateWGKeys(keys *wgKeys) error {
	if keys == nil {
		return errors.New("missing keys")
	}
	if err := validateKeyPair(keys.serverPrivate, keys.serverPublic); err != nil {
		return fmt.Errorf("server key pair: %w", err)
	}
	return nil
}

func writeWGKeysAtomic(dir, path string, keys *wgKeys) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create key directory: %w", err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return fmt.Errorf("secure key directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".wg-keys-*")
	if err != nil {
		return fmt.Errorf("create temporary key file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return fmt.Errorf("secure temporary key file: %w", err)
	}
	content := fmt.Sprintf("%s\n%s\n", keys.serverPrivate, keys.serverPublic)
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return fmt.Errorf("write temporary key file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync temporary key file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary key file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("install key file: %w", err)
	}
	dirHandle, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open key directory for sync: %w", err)
	}
	defer dirHandle.Close()
	if err := dirHandle.Sync(); err != nil {
		return fmt.Errorf("sync key directory: %w", err)
	}
	return nil
}

func loadOrGenerateKeys(dir string) (*wgKeys, error) {
	f := filepath.Join(dir, "wg-keys.dat")
	data, err := os.ReadFile(f)
	if err == nil {
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) != 2 && len(lines) != 4 {
			return nil, fmt.Errorf("invalid key file %s: expected 2 or 4 lines, got %d", f, len(lines))
		}
		keys := &wgKeys{
			serverPrivate: strings.TrimSpace(lines[0]),
			serverPublic:  strings.TrimSpace(lines[1]),
		}
		if err := validateWGKeys(keys); err != nil {
			return nil, fmt.Errorf("invalid key file %s: %w", f, err)
		}
		if len(lines) == 4 {
			if err := validateKeyPair(strings.TrimSpace(lines[2]), strings.TrimSpace(lines[3])); err != nil {
				return nil, fmt.Errorf("invalid legacy client key pair in %s: %w", f, err)
			}
			if err := writeWGKeysAtomic(dir, f, keys); err != nil {
				return nil, fmt.Errorf("migrate key file %s: %w", f, err)
			}
			log.Printf("[WG] Формат %s безопасно мигрирован с 4 строк на 2", f)
		} else if err := os.Chmod(f, 0600); err != nil {
			return nil, fmt.Errorf("secure key file %s: %w", f, err)
		}
		log.Printf("[WG] Ключи загружены из %s", f)
		return keys, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read key file %s: %w", f, err)
	}

	log.Println("[WG] Генерирую новые ключи...")
	sPriv, sPub, err := generateKeyPair()
	if err != nil {
		return nil, err
	}
	keys := &wgKeys{
		serverPrivate: sPriv,
		serverPublic:  sPub,
	}
	if err := validateWGKeys(keys); err != nil {
		return nil, fmt.Errorf("validate generated keys: %w", err)
	}
	if err := writeWGKeysAtomic(dir, f, keys); err != nil {
		return nil, err
	}
	log.Printf("[WG] Ключи сохранены в %s", f)
	return keys, nil
}

func setupFullConeNAT(wgIface string) error {
	log.Println("[NAT] ══════════════════════════════════════")
	if err := ensureIPv4Forwarding(); err != nil {
		natType = "ОШИБКА: IPv4 forwarding"
		return err
	}

	extIface, err := getDefaultInterface()
	if err != nil {
		natType = "ОШИБКА: внешний интерфейс"
		return err
	}
	log.Printf("[NAT] Внешний: %s", extIface)

	if !commandExists("iptables") {
		natType = "NAT не настроен: нет iptables"
		return errors.New(natType)
	}
	if err := setupIptablesNAT(wgIface, extIface); err != nil {
		natType = "ОШИБКА: iptables"
		return err
	}
	natType = "MASQUERADE iptables ✅"

	log.Printf("[NAT] Режим: %s", natType)
	log.Println("[NAT] ══════════════════════════════════════")
	return nil
}

func ensureIPv4Forwarding() error {
	const path = "/proc/sys/net/ipv4/ip_forward"
	current, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if strings.TrimSpace(string(current)) == "1" {
		return nil
	}
	if err := os.WriteFile(path, []byte("1\n"), 0644); err != nil {
		return fmt.Errorf("enable IPv4 forwarding: %w", err)
	}
	current, err = os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("verify IPv4 forwarding: %w", err)
	}
	if strings.TrimSpace(string(current)) != "1" {
		return errors.New("IPv4 forwarding remained disabled")
	}
	return nil
}

func ensureIptablesRule(table, chain string, insert bool, rule ...string) error {
	base := []string{"-w", "5"}
	if table != "filter" {
		base = append(base, "-t", table)
	}
	checkArgs := append(append([]string{}, base...), "-C", chain)
	checkArgs = append(checkArgs, rule...)
	if _, err := runCmd("iptables", checkArgs...); err == nil {
		return nil
	}
	action := "-A"
	if insert {
		action = "-I"
	}
	addArgs := append(append([]string{}, base...), action, chain)
	if insert {
		addArgs = append(addArgs, "1")
	}
	addArgs = append(addArgs, rule...)
	out, err := runCmd("iptables", addArgs...)
	if err != nil {
		return fmt.Errorf("iptables %s/%s: %w: %s", table, chain, err, out)
	}
	return nil
}

func deleteIptablesRule(table, chain string, rule ...string) error {
	base := []string{"-w", "5"}
	if table != "filter" {
		base = append(base, "-t", table)
	}
	for attempts := 0; attempts < 16; attempts++ {
		checkArgs := append(append([]string{}, base...), "-C", chain)
		checkArgs = append(checkArgs, rule...)
		if _, err := runCmd("iptables", checkArgs...); err != nil {
			return nil
		}
		deleteArgs := append(append([]string{}, base...), "-D", chain)
		deleteArgs = append(deleteArgs, rule...)
		out, err := runCmd("iptables", deleteArgs...)
		if err != nil {
			return fmt.Errorf("delete iptables %s/%s: %w: %s", table, chain, err, out)
		}
	}
	return fmt.Errorf("delete iptables %s/%s: too many duplicate rules", table, chain)
}

func setupIptablesNAT(wgIface, extIface string) error {
	comment := []string{"-m", "comment", "--comment", "WDTT_MANAGED"}
	// The server owns tunnel INPUT/FORWARD/NAT policy. Older installer
	// entrypoints installed the same data-plane rules before exec; remove those
	// duplicates while leaving public-port ingress and TCPMSS to the installer.
	installerRules := []struct {
		table  string
		chain  string
		rule   []string
		target string
	}{
		{"filter", "INPUT", []string{"-i", wgIface}, "DROP"},
		{"filter", "FORWARD", []string{"-i", wgIface, "-o", wgIface}, "DROP"},
		{"filter", "FORWARD", []string{"-i", wgIface, "-s", wgServerCIDR, "-o", extIface}, "ACCEPT"},
		{"filter", "FORWARD", []string{"-i", extIface, "-o", wgIface, "-d", wgServerCIDR, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED"}, "ACCEPT"},
		{"filter", "FORWARD", []string{"-i", wgIface}, "DROP"},
		{"filter", "FORWARD", []string{"-o", wgIface}, "DROP"},
		{"nat", "POSTROUTING", []string{"-s", wgServerCIDR, "-o", extIface}, "MASQUERADE"},
	}
	for _, installerOwner := range []string{"WDTT_DOCKER", "WDTT_SETUP"} {
		installerComment := []string{"-m", "comment", "--comment", installerOwner}
		for _, item := range installerRules {
			rule := append(append([]string{}, item.rule...), installerComment...)
			rule = append(rule, "-j", item.target)
			if err := deleteIptablesRule(item.table, item.chain, rule...); err != nil {
				return err
			}
		}
	}
	// Remove the broad forwarding rules written by older versions before
	// installing the directional policy below.
	for _, legacyRule := range [][]string{
		{"-i", wgIface},
		{"-o", wgIface},
		{"-o", wgIface, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED"},
	} {
		legacyRule = append(legacyRule, comment...)
		legacyRule = append(legacyRule, "-j", "ACCEPT")
		if err := deleteIptablesRule("filter", "FORWARD", legacyRule...); err != nil {
			return err
		}
	}

	natRule := []string{"-s", wgServerCIDR, "-o", extIface}
	natRule = append(natRule, comment...)
	natRule = append(natRule, "-j", "MASQUERADE")
	if err := ensureIptablesRule("nat", "POSTROUTING", true, natRule...); err != nil {
		return err
	}

	rules := []struct {
		rule   []string
		target string
	}{
		// Rules are inserted in reverse order so the explicit peer isolation
		// remains first even when the host FORWARD policy is ACCEPT.
		{[]string{"-o", wgIface}, "DROP"},
		{[]string{"-i", wgIface}, "DROP"},
		{[]string{"-i", extIface, "-o", wgIface, "-d", wgServerCIDR, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED"}, "ACCEPT"},
		{[]string{"-i", wgIface, "-s", wgServerCIDR, "-o", extIface}, "ACCEPT"},
		{[]string{"-i", wgIface, "-o", wgIface}, "DROP"},
	}
	for _, item := range rules {
		rule := append(item.rule, comment...)
		rule = append(rule, "-j", item.target)
		if err := ensureIptablesRule("filter", "FORWARD", true, rule...); err != nil {
			return err
		}
	}
	inputRule := []string{"-i", wgIface}
	inputRule = append(inputRule, comment...)
	inputRule = append(inputRule, "-j", "DROP")
	return ensureIptablesRule("filter", "INPUT", true, inputRule...)
}

func startUserspaceWG(keys *wgKeys, wgPort int) (*device.Device, error) {
	runCmdSilent("ip", "link", "del", wgIfaceName)
	time.Sleep(100 * time.Millisecond)

	tunDev, err := tun.CreateTUN(wgIfaceName, wgMTU)
	if err != nil {
		return nil, fmt.Errorf("CreateTUN: %w", err)
	}

	ifaceName, err := tunDev.Name()
	if err != nil {
		tunDev.Close()
		return nil, fmt.Errorf("TUN name: %w", err)
	}

	logger := device.NewLogger(device.LogLevelError, "[WG] ")
	bind := newLoopbackBind()
	dev := device.NewDevice(tunDev, bind, logger)

	serverPrivHex, err := b64ToHex(keys.serverPrivate)
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("decode server private key: %w", err)
	}

	if err := dev.IpcSet(fmt.Sprintf(
		"private_key=%s\nlisten_port=%d\n",
		serverPrivHex, wgPort,
	)); err != nil {
		dev.Close()
		return nil, fmt.Errorf("IpcSet: %w", err)
	}

	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("device.Up: %w", err)
	}

	if err := configureInterface(ifaceName); err != nil {
		dev.Close()
		return nil, err
	}

	if err := setupFullConeNAT(ifaceName); err != nil {
		dev.Close()
		return nil, err
	}

	go func() {
		uapiFile, err := ipc.UAPIOpen(ifaceName)
		if err != nil {
			return
		}
		defer uapiFile.Close()

		uapi, err := ipc.UAPIListen(ifaceName, uapiFile)
		if err != nil {
			return
		}
		defer uapi.Close()
		for {
			c, err := uapi.Accept()
			if err != nil {
				return
			}
			go dev.IpcHandle(c)
		}
	}()

	log.Printf("[WG] Запущен на порту %d", wgPort)
	return dev, nil
}

func configureInterface(ifaceName string) error {
	for _, cmd := range [][]string{
		{"ip", "addr", "add", wgServerCIDR, "dev", ifaceName},
		{"ip", "link", "set", "mtu", fmt.Sprintf("%d", wgMTU), "dev", ifaceName},
		{"ip", "link", "set", ifaceName, "up"},
	} {
		out, err := runCmd(cmd[0], cmd[1:]...)
		if err != nil && !strings.Contains(out, "File exists") {
			return fmt.Errorf("%s: %s", strings.Join(cmd, " "), out)
		}
	}
	return nil
}

func buildClientConfig(serverPublic, clientPrivate, clientIP, clientPort string) string {
	return fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/32
DNS = %s
MTU = %d

[Peer]
PublicKey = %s
AllowedIPs = 0.0.0.0/0
Endpoint = 127.0.0.1:%s
PersistentKeepalive = %d`,
		clientPrivate, clientIP, dns, wgMTU,
		serverPublic, clientPort, keepalive,
	)
}

type getConfRequest struct {
	ClientPort   string
	DeviceID     string
	Password     string
	GenerationID string
	WorkerID     string
}

func (r getConfRequest) IsLifecycleV2() bool {
	return r.GenerationID != ""
}

func validateLifecycleID(name, value string) error {
	if len(value) == 0 || len(value) > 64 {
		return fmt.Errorf("%s must contain 1 to 64 characters", name)
	}
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == ':' || ch == '-' {
			continue
		}
		return fmt.Errorf("%s contains unsupported byte 0x%02x", name, ch)
	}
	return nil
}

func parseGetConfRequest(packet []byte) (getConfRequest, bool, error) {
	const prefix = "GETCONF:"
	raw := string(packet)
	if !strings.HasPrefix(raw, prefix) {
		return getConfRequest{}, false, nil
	}

	parts := strings.Split(strings.TrimSpace(strings.TrimPrefix(raw, prefix)), "|")
	if len(parts) != 3 && len(parts) != 5 {
		return getConfRequest{}, true, errors.New("GETCONF must contain either 3 legacy fields or 5 lifecycle fields")
	}
	port, err := strconv.Atoi(parts[0])
	if err != nil || port < 1 || port > 65535 {
		return getConfRequest{}, true, errors.New("GETCONF contains an invalid client port")
	}
	if err := validateDeviceID(parts[1]); err != nil {
		return getConfRequest{}, true, fmt.Errorf("GETCONF contains an invalid device ID: %w", err)
	}
	if len(parts[2]) == 0 || len(parts[2]) > 128 {
		return getConfRequest{}, true, errors.New("GETCONF contains an invalid password")
	}
	request := getConfRequest{
		ClientPort: parts[0],
		DeviceID:   parts[1],
		Password:   parts[2],
	}
	if len(parts) == 5 {
		if err := validateLifecycleID("generation ID", parts[3]); err != nil {
			return getConfRequest{}, true, fmt.Errorf("GETCONF contains an invalid generation ID: %w", err)
		}
		if err := validateLifecycleID("worker ID", parts[4]); err != nil {
			return getConfRequest{}, true, fmt.Errorf("GETCONF contains an invalid worker ID: %w", err)
		}
		request.GenerationID = parts[3]
		request.WorkerID = parts[4]
	}
	return request, true, nil
}

func provisionClientConfig(wgDev *device.Device, keys *wgKeys, request getConfRequest, connPassword string, connIsMainPass bool) (string, string, error) {
	peerMutationMu.Lock()
	defer peerMutationMu.Unlock()

	dbMutex.Lock()
	isMainPass := connIsMainPass && connPassword == db.MainPassword
	entry, isGeneratedPassword := db.Passwords[connPassword]
	valid := isMainPass || (isGeneratedPassword && !isPasswordExpired(entry))
	if !valid {
		response := "DENIED:wrong_password"
		if isGeneratedPassword && isPasswordExpired(entry) {
			response = "DENIED:expired"
		}
		dbMutex.Unlock()
		return "", response, nil
	}
	if isGeneratedPassword && entry.IsDeactivated {
		dbMutex.Unlock()
		return "", "DENIED:deactivated", nil
	}
	if isGeneratedPassword && entry.DeviceID != "" && entry.DeviceID != request.DeviceID {
		dbMutex.Unlock()
		return "", "DENIED:device_mismatch", nil
	}
	generatedOwner, ownedByGeneratedPassword := generatedPasswordForDevice(db, request.DeviceID)
	if ownedByGeneratedPassword && (!isGeneratedPassword || generatedOwner != connPassword) {
		dbMutex.Unlock()
		return "", "DENIED:device_mismatch", nil
	}

	dev, exists := db.Devices[request.DeviceID]
	if exists && !connectionOwnsDevice(db, request.DeviceID, connPassword, isMainPass) {
		dbMutex.Unlock()
		return "", "DENIED:device_mismatch", nil
	}

	boundPassword := false
	if isGeneratedPassword && entry.DeviceID == "" {
		entry.DeviceID = request.DeviceID
		boundPassword = true
	}

	createdDevice := false
	if !exists {
		clientIP := getNextIP()
		dbMutex.Unlock()

		privateKey, publicKey, err := generateKeyPair()
		if err != nil || clientIP == "" {
			dbMutex.Lock()
			if boundPassword && entry.DeviceID == request.DeviceID {
				entry.DeviceID = ""
			}
			dbMutex.Unlock()
			if err == nil {
				err = errors.New("WireGuard address pool is exhausted")
			}
			return "", "NOCONF", err
		}

		dev = &ClientDevice{
			DeviceID: request.DeviceID,
			IP:       clientIP,
			PrivKey:  privateKey,
			PubKey:   publicKey,
		}
		dbMutex.Lock()
		db.Devices[request.DeviceID] = dev
		createdDevice = true
	}

	deviceSnapshot := *dev
	dbMutex.Unlock()

	// Persisted peers are restored before the relay listener starts. Only a
	// newly allocated device needs to mutate the WireGuard peer table here;
	// the remaining relay connections for that device reuse the existing peer.
	if createdDevice {
		if err := upsertPeerInWG(wgDev, &deviceSnapshot); err != nil {
			dbMutex.Lock()
			if current := db.Devices[request.DeviceID]; current != nil && current.PubKey == deviceSnapshot.PubKey {
				delete(db.Devices, request.DeviceID)
			}
			if boundPassword && entry.DeviceID == request.DeviceID {
				entry.DeviceID = ""
			}
			dbMutex.Unlock()
			return "", "NOCONF", err
		}
	}
	// A new device or password binding must be durable before GETCONF succeeds.
	// A dirty revision also covers a retry after an earlier synchronous save
	// failure. Established clients therefore do not rewrite the database once
	// per relay worker.
	if createdDevice || boundPassword || dbRevision.Load() > dbSavedRevision.Load() {
		if err := saveDBCritical(); err != nil {
			return "", "NOCONF", err
		}
	}

	return buildClientConfig(keys.serverPublic, deviceSnapshot.PrivKey, deviceSnapshot.IP, request.ClientPort), "", nil
}

func addTraffic(total, passwordTotal *int64, bytes int, trackPassword bool) {
	if bytes <= 0 {
		return
	}
	atomic.AddInt64(total, int64(bytes))
	if trackPassword {
		atomic.AddInt64(passwordTotal, int64(bytes))
	}
}

func isRelayKeepalive(packet []byte) bool {
	return len(packet) == 1 && (packet[0] == 0x00 || packet[0] == 0xFF)
}

const relayDeadlineRefreshInterval = 5 * time.Second

type readDeadlineSetter interface {
	SetReadDeadline(time.Time) error
}

type relayReadDeadlineRefresher struct {
	nextRefresh time.Time
}

func (r *relayReadDeadlineRefresher) refresh(conn readDeadlineSetter, now time.Time, idleTimeout time.Duration) error {
	if !r.nextRefresh.IsZero() && now.Before(r.nextRefresh) {
		return nil
	}
	// The extra interval keeps the effective idle timeout from becoming
	// shorter when the final packet arrives just before the next refresh.
	if err := conn.SetReadDeadline(now.Add(idleTimeout + relayDeadlineRefreshInterval)); err != nil {
		return err
	}
	r.nextRefresh = now.Add(relayDeadlineRefreshInterval)
	return nil
}

func readRelayPacketWithDeadline(clientConn net.Conn, buf []byte, deadlineForRead func() time.Time) ([]byte, error) {
	for {
		if err := clientConn.SetReadDeadline(deadlineForRead()); err != nil {
			return nil, err
		}
		n, err := clientConn.Read(buf)
		if err != nil {
			return nil, err
		}
		packet := buf[:n]
		if len(packet) == 0 || isRelayKeepalive(packet) {
			continue
		}
		return packet, nil
	}
}

func readRelayPacket(clientConn net.Conn, buf []byte, idleTimeout time.Duration) ([]byte, error) {
	return readRelayPacketWithDeadline(clientConn, buf, func() time.Time {
		return time.Now().Add(idleTimeout)
	})
}

func readInitialRelayPacket(clientConn net.Conn, buf []byte, timeout time.Duration) ([]byte, error) {
	deadline := time.Now().Add(timeout)
	return readRelayPacketWithDeadline(clientConn, buf, func() time.Time {
		return deadline
	})
}

type relayIdleTimeouts struct {
	legacy      time.Duration
	lifecycleV2 time.Duration
}

func (t relayIdleTimeouts) forRequest(request getConfRequest) time.Duration {
	if request.IsLifecycleV2() {
		return t.lifecycleV2
	}
	return t.legacy
}

func handleConn(
	ctx context.Context,
	clientConn net.Conn,
	identity wrapIdentity,
	wgEndpoint string,
	wgDev *device.Device,
	keys *wgKeys,
	lifecycleRegistry *relayLifecycleRegistry,
	idleTimeouts relayIdleTimeouts,
) {
	defer clientConn.Close()
	connCtx, connCancel := context.WithCancel(ctx)
	defer connCancel()
	stopConnectionDeadline := context.AfterFunc(connCtx, func() {
		_ = clientConn.SetDeadline(time.Now())
	})
	defer stopConnectionDeadline()

	atomic.AddInt64(&admittedConns, 1)

	dtlsConn, ok := clientConn.(*dtls.Conn)
	if !ok {
		return
	}

	hctx, hcancel := context.WithTimeout(connCtx, dtlsHandshakeTimeout)
	if err := dtlsConn.HandshakeContext(hctx); err != nil {
		hcancel()
		atomic.AddInt64(&failedHandshakes, 1)
		return
	}
	hcancel()
	atomic.AddInt64(&successfulHandshakes, 1)

	connPassword := identity.Password
	connIsMainPass := identity.IsMain

	accessState := getPasswordAccessState(connPassword, connIsMainPass)
	passwordActive := accessState.IsActive
	if !passwordActive() {
		log.Printf("[WRAP] Отказ: неактивный ключ %s для %s", maskPassword(connPassword), clientConn.RemoteAddr())
		return
	}
	var relayModeTracked bool
	var relayModeV2 bool
	var relayActive bool
	trackRelayMode := func(v2 bool) {
		if relayModeTracked {
			return
		}
		relayModeTracked = true
		relayModeV2 = v2
	}
	defer func() {
		if !relayActive {
			return
		}
		atomic.AddInt32(&activeConns, -1)
		if relayModeV2 {
			atomic.AddInt32(&activeV2Conns, -1)
		} else {
			atomic.AddInt32(&activeLegacyConns, -1)
		}
	}()

	buf := make([]byte, 1600)
	firstPacket, err := readInitialRelayPacket(clientConn, buf, initialRelayTimeout)
	if err != nil {
		return
	}
	firstStr := string(firstPacket)
	var lifecycleRegistration *relayLifecycleRegistration
	relayIdleTimeout := idleTimeouts.legacy

	getConf, isGetConf, getConfErr := parseGetConfRequest(firstPacket)
	if isGetConf {
		if getConfErr != nil {
			_, _ = clientConn.Write([]byte("DENIED:malformed_getconf"))
			log.Printf("[WG] Отказ: некорректный GETCONF от %s: %v", clientConn.RemoteAddr(), getConfErr)
			return
		}
		relayIdleTimeout = idleTimeouts.forRequest(getConf)
		deviceID := getConf.DeviceID
		password := getConf.Password

		if password != connPassword {
			_, _ = clientConn.Write([]byte("DENIED:password_mismatch"))
			log.Printf("[WG] Отказ: GETCONF-пароль не совпадает с WRAP-ключом для %s", deviceID)
			return
		}

		config, response, provisionErr := provisionClientConfig(wgDev, keys, getConf, connPassword, connIsMainPass)
		if provisionErr != nil {
			log.Printf("[WG] Не удалось подготовить конфигурацию для %s: %v", deviceID, provisionErr)
		}
		if response != "" {
			_, _ = clientConn.Write([]byte(response))
			if response != "NOCONF" {
				log.Printf("[WG] Отказ %s для устройства %s", response, deviceID)
			}
			return
		}
		if getConf.IsLifecycleV2() {
			var accepted bool
			lifecycleRegistration, accepted = lifecycleRegistry.RegisterV2(
				deviceID, getConf.GenerationID, getConf.WorkerID, connCancel,
			)
			if !accepted {
				_, _ = clientConn.Write([]byte("DENIED:stale_generation"))
				log.Printf("[LIFECYCLE] Отклонён поздний воркер %s/%s устройства %s", getConf.GenerationID, getConf.WorkerID, deviceID)
				return
			}
		} else {
			lifecycleRegistration = lifecycleRegistry.RegisterLegacy(deviceID, connCancel)
		}
		if lifecycleRegistration != nil {
			defer lifecycleRegistration.Release()
		}
		trackRelayMode(getConf.IsLifecycleV2())
		if _, err := clientConn.Write([]byte(config)); err != nil {
			return
		}

		firstPacket, err = readRelayPacket(clientConn, buf, relayIdleTimeout)
		if err != nil {
			return
		}
		firstStr = string(firstPacket)
	}
	if !isGetConf {
		trackRelayMode(false)
	}

	for firstStr == "READY" {
		if _, err := clientConn.Write([]byte("READY_OK")); err != nil {
			return
		}
		firstPacket, err = readRelayPacket(clientConn, buf, relayIdleTimeout)
		if err != nil {
			return
		}
		firstStr = string(firstPacket)
	}

	if !passwordActive() {
		return
	}

	wgConn, err := net.Dial("udp", wgEndpoint)
	if err != nil {
		return
	}
	defer wgConn.Close()

	if uc, ok := wgConn.(*net.UDPConn); ok {
		uc.SetReadBuffer(2 * 1024 * 1024)
		uc.SetWriteBuffer(2 * 1024 * 1024)
	}

	var localUpBytes int64
	var localDownBytes int64

	if _, err := wgConn.Write(firstPacket); err != nil {
		return
	}
	atomic.AddInt64(&totalConns, 1)
	atomic.AddInt32(&activeConns, 1)
	if relayModeV2 {
		atomic.AddInt32(&activeV2Conns, 1)
	} else {
		atomic.AddInt32(&activeLegacyConns, 1)
	}
	relayActive = true
	addTraffic(&totalBytesFromClient, &localUpBytes, len(firstPacket), !connIsMainPass)

	pctx, pcancel := context.WithCancel(connCtx)
	defer pcancel()

	stopProxyDeadline := context.AfterFunc(pctx, func() {
		_ = clientConn.SetDeadline(time.Now())
		_ = wgConn.SetDeadline(time.Now())
	})
	defer stopProxyDeadline()

	flushStats := func() bool {
		up := atomic.SwapInt64(&localUpBytes, 0)
		down := atomic.SwapInt64(&localDownBytes, 0)

		dbMutex.Lock()
		defer dbMutex.Unlock()

		e, ok := db.Passwords[connPassword]
		if !ok || e == nil {
			return false
		}

		e.UpBytes += up
		e.DownBytes += down
		if up != 0 || down != 0 {
			saveDBLazy()
		}
		return !isPasswordExpired(e) && !e.IsDeactivated
	}

	var proxyWg sync.WaitGroup
	proxyWg.Add(2)

	if !connIsMainPass {
		proxyWg.Add(1)
		go func() {
			defer proxyWg.Done()
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()

			for {
				select {
				case <-pctx.Done():
					flushStats()
					return
				case <-ticker.C:
					if !flushStats() {
						pcancel()
						return
					}
				}
			}
		}()
	}

	// Направление: Клиент -> WireGuard (Upload)
	go func() {
		defer proxyWg.Done()
		defer pcancel()
		b := getBuf()
		defer putBuf(b)
		var deadline relayReadDeadlineRefresher

		for {
			if pctx.Err() != nil {
				return
			}
			if err := deadline.refresh(clientConn, time.Now(), relayIdleTimeout); err != nil {
				return
			}

			nn, err := clientConn.Read(*b)
			if err != nil {
				return
			}

			if isRelayKeepalive((*b)[:nn]) {
				continue
			}
			if !passwordActive() {
				return
			}

			addTraffic(&totalBytesFromClient, &localUpBytes, nn, !connIsMainPass)
			if _, err := wgConn.Write((*b)[:nn]); err != nil {
				return
			}
		}
	}()

	// Направление: WireGuard -> Клиент (Download)
	go func() {
		defer proxyWg.Done()
		defer pcancel()
		b := getBuf()
		defer putBuf(b)

		for {
			if pctx.Err() != nil {
				return
			}

			nn, err := wgConn.Read(*b)
			if err != nil {
				return
			}
			if !passwordActive() {
				return
			}

			addTraffic(&totalBytesToClient, &localDownBytes, nn, !connIsMainPass)
			if _, err := clientConn.Write((*b)[:nn]); err != nil {
				return
			}
		}
	}()

	proxyWg.Wait()

	// Добавлен финальный сброс статистики после завершения работы всех прокси-горутин
	if !connIsMainPass {
		flushStats()
	}
}
