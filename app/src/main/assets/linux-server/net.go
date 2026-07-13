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

func enableBBR() {
	log.Println("[SYS] Оптимизация TCP...")
	out, _ := runCmd("bash", "-c", "sysctl net.ipv4.tcp_congestion_control")
	if strings.Contains(out, "bbr") {
		log.Println("[SYS] BBR уже активен ✓")
		return
	}
	cmds := [][]string{
		{"sysctl", "-w", "net.core.default_qdisc=fq"},
		{"sysctl", "-w", "net.ipv4.tcp_congestion_control=bbr"},
		{"sysctl", "-w", "net.core.rmem_max=25165824"},
		{"sysctl", "-w", "net.core.wmem_max=25165824"},
		{"sysctl", "-w", "net.ipv4.tcp_rmem=4096 87380 25165824"},
		{"sysctl", "-w", "net.ipv4.tcp_wmem=4096 65536 25165824"},
	}
	for _, cmd := range cmds {
		runCmd(cmd[0], cmd[1:]...)
	}
	log.Println("[SYS] BBR включен ✓")
}

var (
	totalBytesFromClient int64
	totalBytesToClient   int64
	activeConns          int32
	totalConns           int64
	rejectedConns        int64
	natType              string = "Инициализация..."
	serverStartTime      time.Time
)

func statsLoop(ctx context.Context, configDir string) {
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
			total := atomic.LoadInt64(&totalConns)
			rejected := atomic.LoadInt64(&rejectedConns)
			uptime := time.Since(serverStartTime)

			dbMutex.Lock()
			numPasswords := len(db.Passwords)
			numDevices := len(db.Devices)
			dbMutex.Unlock()

			uptimeStr := formatUptime(uptime)
			downGB := float64(toC) / (1024 * 1024 * 1024)
			upGB := float64(fromC) / (1024 * 1024 * 1024)

			log.Printf("[СТАТ] Активных: %d | Всего соединений: %d | Отклонено лимитом: %d | Uptime: %s | Получено: %.2f GB | Отправлено: %.2f GB | Паролей: %d | Устройств: %d",
				active, total, rejected, uptimeStr, downGB, upGB, numPasswords, numDevices)

			statsJSON, _ := json.Marshal(map[string]interface{}{
				"active":    active,
				"total":     total,
				"rejected":  rejected,
				"nat":       natType,
				"uptime":    uptimeStr,
				"down_gb":   fmt.Sprintf("%.2f", downGB),
				"up_gb":     fmt.Sprintf("%.2f", upGB),
				"passwords": numPasswords,
				"devices":   numDevices,
				"timestamp": time.Now().Unix(),
			})
			os.WriteFile(statsFile, statsJSON, 0644)
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

func isNetTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
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
	serverPrivate, serverPublic, clientPrivate, clientPublic string
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
	if err := validateKeyPair(keys.clientPrivate, keys.clientPublic); err != nil {
		return fmt.Errorf("client key pair: %w", err)
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
	content := fmt.Sprintf("%s\n%s\n%s\n%s\n",
		keys.serverPrivate, keys.serverPublic,
		keys.clientPrivate, keys.clientPublic)
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
		if len(lines) != 4 {
			return nil, fmt.Errorf("invalid key file %s: expected 4 lines, got %d", f, len(lines))
		}
		keys := &wgKeys{
			serverPrivate: strings.TrimSpace(lines[0]),
			serverPublic:  strings.TrimSpace(lines[1]),
			clientPrivate: strings.TrimSpace(lines[2]),
			clientPublic:  strings.TrimSpace(lines[3]),
		}
		if err := validateWGKeys(keys); err != nil {
			return nil, fmt.Errorf("invalid key file %s: %w", f, err)
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
	cPriv, cPub, err := generateKeyPair()
	if err != nil {
		return nil, err
	}
	keys := &wgKeys{
		serverPrivate: sPriv,
		serverPublic:  sPub,
		clientPrivate: cPriv,
		clientPublic:  cPub,
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

	switch {
	case commandExists("iptables"):
		if err := setupIptablesNAT(wgIface, extIface); err != nil {
			natType = "ОШИБКА: iptables"
			return err
		}
		natType = "MASQUERADE iptables ✅"
	case commandExists("nft"):
		if err := setupNftNAT(wgIface, extIface); err != nil {
			natType = "ОШИБКА: nftables"
			return err
		}
		natType = "MASQUERADE nft ✅"
	default:
		natType = "NAT не настроен: нет iptables/nft"
		return errors.New(natType)
	}

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

func setupIptablesNAT(wgIface, extIface string) error {
	comment := []string{"-m", "comment", "--comment", "WDTT_MANAGED"}
	natRule := []string{"-s", wgServerCIDR, "-o", extIface}
	natRule = append(natRule, comment...)
	natRule = append(natRule, "-j", "MASQUERADE")
	if err := ensureIptablesRule("nat", "POSTROUTING", true, natRule...); err != nil {
		return err
	}

	fromRule := []string{"-i", wgIface}
	fromRule = append(fromRule, comment...)
	fromRule = append(fromRule, "-j", "ACCEPT")
	if err := ensureIptablesRule("filter", "FORWARD", false, fromRule...); err != nil {
		return err
	}
	toRule := []string{"-o", wgIface}
	toRule = append(toRule, comment...)
	toRule = append(toRule, "-j", "ACCEPT")
	return ensureIptablesRule("filter", "FORWARD", false, toRule...)
}

func runNft(args ...string) error {
	out, err := runCmd("nft", args...)
	if err != nil {
		return fmt.Errorf("nft %s: %w: %s", strings.Join(args, " "), err, out)
	}
	return nil
}

func setupNftNAT(wgIface, extIface string) error {
	if _, err := runCmd("nft", "list", "table", "inet", "wdtt"); err == nil {
		if err := runNft("delete", "table", "inet", "wdtt"); err != nil {
			return err
		}
	}
	commands := [][]string{
		{"add", "table", "inet", "wdtt"},
		{"add", "chain", "inet", "wdtt", "postrouting", "{ type nat hook postrouting priority srcnat; policy accept; }"},
		{"add", "rule", "inet", "wdtt", "postrouting", "ip", "saddr", wgServerCIDR, "oifname", extIface, "masquerade"},
		{"add", "chain", "inet", "wdtt", "forward", "{ type filter hook forward priority filter; policy accept; }"},
		{"add", "rule", "inet", "wdtt", "forward", "iifname", wgIface, "accept"},
		{"add", "rule", "inet", "wdtt", "forward", "oifname", wgIface, "accept"},
	}
	for _, command := range commands {
		if err := runNft(command...); err != nil {
			return err
		}
	}
	return nil
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

	serverPrivHex, _ := b64ToHex(keys.serverPrivate)

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

func handleConn(ctx context.Context, clientConn net.Conn, authSource *wrapPacketListener, wgEndpoint string, wgDev *device.Device, keys *wgKeys) {
	// Добавлен defer для предотвращения утечки сокетов при ошибках на любом этапе функции
	defer clientConn.Close()

	atomic.AddInt64(&totalConns, 1)

	dtlsConn, ok := clientConn.(*dtls.Conn)
	if !ok {
		return
	}

	hctx, hcancel := context.WithTimeout(ctx, dtlsHandshakeTimeout)
	if err := dtlsConn.HandshakeContext(hctx); err != nil {
		hcancel()
		return
	}
	hcancel()

	identity, ok := authSource.IdentityFor(clientConn.RemoteAddr())
	if !ok {
		log.Printf("[WRAP] Отказ: не удалось связать DTLS с WRAP-ключом для %s", clientConn.RemoteAddr())
		return
	}
	connPassword := identity.Password
	connIsMainPass := identity.IsMain

	passwordActive := func() bool {
		if connIsMainPass {
			dbMutex.RLock()
			active := db.MainPassword == connPassword
			dbMutex.RUnlock()
			return active
		}

		dbMutex.RLock()
		entry, exists := db.Passwords[connPassword]
		active := exists && entry != nil && !isPasswordExpired(entry) && !entry.IsDeactivated
		dbMutex.RUnlock()
		return active
	}
	if !passwordActive() {
		log.Printf("[WRAP] Отказ: неактивный ключ %s для %s", maskPassword(connPassword), clientConn.RemoteAddr())
		return
	}

	atomic.AddInt32(&activeConns, 1)
	defer atomic.AddInt32(&activeConns, -1)

	buf := make([]byte, 1600)
	clientConn.SetReadDeadline(time.Now().Add(30 * time.Second))
	n, err := clientConn.Read(buf)
	if err != nil {
		return
	}
	clientConn.SetReadDeadline(time.Time{})

	firstPacket := buf[:n]
	firstStr := string(firstPacket)

	if strings.HasPrefix(firstStr, "GETCONF:") {
		parts := strings.Split(strings.TrimSpace(strings.TrimPrefix(firstStr, "GETCONF:")), "|")
		clientPort := "9000"
		deviceID := "unknown"
		password := ""
		if len(parts) > 0 {
			clientPort = parts[0]
		}
		if len(parts) > 1 {
			deviceID = parts[1]
		}
		if len(parts) > 2 {
			password = parts[2]
		}

		if password != connPassword {
			_, _ = clientConn.Write([]byte("DENIED:password_mismatch"))
			log.Printf("[WG] Отказ: GETCONF-пароль не совпадает с WRAP-ключом для %s", deviceID)
			return
		}

		dbMutex.Lock()

		isMainPass := connIsMainPass && password == db.MainPassword
		entry, isGenPass := db.Passwords[connPassword]
		valid := isMainPass || (isGenPass && !isPasswordExpired(entry))

		if valid && isGenPass && entry.IsDeactivated {
			clientConn.Write([]byte("DENIED:deactivated"))
			log.Printf("[WG] Отказ: пароль %s деактивирован, запрос от %s", maskPassword(password), deviceID)
			dbMutex.Unlock()
			return
		} else if valid && isGenPass && entry.DeviceID != "" && entry.DeviceID != deviceID {
			clientConn.Write([]byte("DENIED:device_mismatch"))
			log.Printf("[WG] Отказ: пароль %s привязан к %s, запрос от %s", maskPassword(password), entry.DeviceID, deviceID)
			dbMutex.Unlock()
			return
		} else if valid {
			boundPassword := false
			if isGenPass && entry.DeviceID == "" {
				entry.DeviceID = deviceID
				boundPassword = true
				saveDBLazy()
				log.Printf("[WG] Пароль %s привязан к устройству %s", maskPassword(password), deviceID)
			}

			dev, exists := db.Devices[deviceID]
			createdDevice := false
			if !exists {
				dev = &ClientDevice{DeviceID: deviceID, IP: getNextIP()}
				privB64, pubB64, keyErr := generateKeyPair()
				if keyErr == nil && dev.IP != "" {
					dev.PrivKey = privB64
					dev.PubKey = pubB64
					db.Devices[deviceID] = dev
					createdDevice = true
					saveDBLazy()
					log.Printf("[WG] Новое устройство %s (IP: %s)", deviceID, dev.IP)
				} else {
					dev = nil
				}
			}
			if dev != nil {
				if err := upsertPeerInWG(wgDev, dev); err != nil {
					log.Printf("[WG] Не удалось настроить peer %s: %v", deviceID, err)
					if createdDevice {
						delete(db.Devices, deviceID)
					}
					if boundPassword {
						entry.DeviceID = ""
					}
					saveDBLazy()
					_, _ = clientConn.Write([]byte("NOCONF"))
					dbMutex.Unlock()
					return
				}
				clientConn.Write([]byte(buildClientConfig(keys.serverPublic, dev.PrivKey, dev.IP, clientPort)))
			} else {
				if boundPassword {
					entry.DeviceID = ""
					saveDBLazy()
				}
				clientConn.Write([]byte("NOCONF"))
			}
			dbMutex.Unlock()
			if dev == nil {
				return
			}
		} else {
			if isGenPass && isPasswordExpired(entry) {
				clientConn.Write([]byte("DENIED:expired"))
				log.Printf("[WG] Отказ: пароль %s истёк, от %s", maskPassword(password), deviceID)
			} else {
				clientConn.Write([]byte("DENIED:wrong_password"))
				log.Printf("[WG] Отказ (неверный пароль) от %s", deviceID)
			}
			dbMutex.Unlock()
			return
		}

		clientConn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		n, err = clientConn.Read(buf)
		if err != nil {
			return
		}
		clientConn.SetReadDeadline(time.Time{})
		firstPacket = buf[:n]
		firstStr = string(firstPacket)
	}

	if firstStr == "READY" {
		clientConn.Write([]byte("READY_OK"))
		clientConn.SetReadDeadline(time.Now().Add(10 * time.Minute))
		n, err = clientConn.Read(buf)
		if err != nil {
			return
		}
		clientConn.SetReadDeadline(time.Time{})
		firstPacket = buf[:n]
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
	atomic.AddInt64(&totalBytesFromClient, int64(len(firstPacket)))
	if !connIsMainPass {
		atomic.AddInt64(&localUpBytes, int64(len(firstPacket)))
	}

	pctx, pcancel := context.WithCancel(ctx)
	defer pcancel()

	context.AfterFunc(pctx, func() {
		clientConn.SetDeadline(time.Now())
		wgConn.SetDeadline(time.Now())
	})

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

		var lastDeadlineUpdate time.Time
		var localFromClient int64
		var localPassUp int64

		// Гарантированный сброс накопленных данных при выходе из горутины
		defer func() {
			if localFromClient > 0 {
				atomic.AddInt64(&totalBytesFromClient, localFromClient)
			}
			if localPassUp > 0 {
				atomic.AddInt64(&localUpBytes, localPassUp)
			}
		}()

		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()

		for {
			select {
			case <-pctx.Done():
				return
			case <-tick.C:
				if localFromClient > 0 {
					atomic.AddInt64(&totalBytesFromClient, localFromClient)
					localFromClient = 0
				}
				if localPassUp > 0 {
					atomic.AddInt64(&localUpBytes, localPassUp)
					localPassUp = 0
				}
			default:
				// Вызываем дедлайн только раз в 15 секунд, а не на каждый пакет
				now := time.Now()
				if now.Sub(lastDeadlineUpdate) > 15*time.Second {
					clientConn.SetReadDeadline(now.Add(30 * time.Minute))
					lastDeadlineUpdate = now
				}

				nn, err := clientConn.Read(*b)
				if err != nil {
					return
				}

				if nn == 1 && (*b)[0] == 0xFF {
					continue
				}
				if !passwordActive() {
					return
				}

				localFromClient += int64(nn)
				if !connIsMainPass {
					localPassUp += int64(nn)
				}

				if _, err := wgConn.Write((*b)[:nn]); err != nil {
					return
				}
			}
		}
	}()

	// Направление: WireGuard -> Клиент (Download)
	go func() {
		defer proxyWg.Done()
		defer pcancel()
		b := getBuf()
		defer putBuf(b)

		var lastDeadlineUpdate time.Time
		var localToClient int64
		var localPassDown int64

		// Гарантированный сброс накопленных данных при выходе из горутины
		defer func() {
			if localToClient > 0 {
				atomic.AddInt64(&totalBytesToClient, localToClient)
			}
			if localPassDown > 0 {
				atomic.AddInt64(&localDownBytes, localPassDown)
			}
		}()

		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()

		for {
			select {
			case <-pctx.Done():
				return
			case <-tick.C:
				if localToClient > 0 {
					atomic.AddInt64(&totalBytesToClient, localToClient)
					localToClient = 0
				}
				if localPassDown > 0 {
					atomic.AddInt64(&localDownBytes, localPassDown)
					localPassDown = 0
				}
			default:
				// Вызываем дедлайн только раз в 15 секунд
				now := time.Now()
				if now.Sub(lastDeadlineUpdate) > 15*time.Second {
					wgConn.SetReadDeadline(now.Add(30 * time.Minute))
					lastDeadlineUpdate = now
				}

				nn, err := wgConn.Read(*b)
				if err != nil {
					if isNetTimeout(err) {
						if pctx.Err() != nil {
							return
						}
						continue
					}
					return
				}
				if !passwordActive() {
					return
				}

				localToClient += int64(nn)
				if !connIsMainPass {
					localPassDown += int64(nn)
				}

				if _, err := clientConn.Write((*b)[:nn]); err != nil {
					return
				}
			}
		}
	}()

	proxyWg.Wait()

	// Добавлен финальный сброс статистики после завершения работы всех прокси-горутин
	if !connIsMainPass {
		flushStats()
	}
}
