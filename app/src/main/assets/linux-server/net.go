package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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

	"golang.zx2c4.com/wireguard/conn"
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
			uptime := time.Since(serverStartTime)

			dbMutex.Lock()
			numPasswords := len(db.Passwords)
			numDevices := len(db.Devices)
			dbMutex.Unlock()

			uptimeStr := formatUptime(uptime)
			downGB := float64(toC) / (1024 * 1024 * 1024)
			upGB := float64(fromC) / (1024 * 1024 * 1024)

			log.Printf("[СТАТ] Активных: %d | Всего соединений: %d | Uptime: %s | Получено: %.2f GB | Отправлено: %.2f GB | Паролей: %d | Устройств: %d",
				active, total, uptimeStr, downGB, upGB, numPasswords, numDevices)

			statsJSON, _ := json.Marshal(map[string]interface{}{
				"active":    active,
				"total":     total,
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

func getDefaultInterface() string {
	out := runCmdSilent("bash", "-c", "ip route show default | awk '/default/ {print $5}' | head -1")
	if out != "" {
		return strings.TrimSpace(out)
	}
	out = runCmdSilent("bash", "-c", "ip -o link show | awk -F': ' '{print $2}' | grep -v -E 'lo|wg|tun|wdtt' | head -1")
	if out != "" {
		return strings.TrimSpace(out)
	}
	return "eth0"
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

func loadOrGenerateKeys(dir string) (*wgKeys, error) {
	f := filepath.Join(dir, "wg-keys.dat")
	if data, err := os.ReadFile(f); err == nil {
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) >= 4 {
			keys := &wgKeys{
				serverPrivate: strings.TrimSpace(lines[0]),
				serverPublic:  strings.TrimSpace(lines[1]),
				clientPrivate: strings.TrimSpace(lines[2]),
				clientPublic:  strings.TrimSpace(lines[3]),
			}
			for _, k := range []string{keys.serverPrivate, keys.serverPublic,
				keys.clientPrivate, keys.clientPublic} {
				if _, err := b64ToHex(k); err != nil {
					goto generate
				}
			}
			log.Printf("[WG] Ключи загружены из %s", f)
			return keys, nil
		}
	}
generate:
	log.Println("[WG] Генерирую новые ключи...")
	sPriv, sPub, err := generateKeyPair()
	if err != nil {
		return nil, err
	}
	cPriv, cPub, err := generateKeyPair()
	if err != nil {
		return nil, err
	}
	keys := &wgKeys{sPriv, sPub, cPriv, cPub}
	os.MkdirAll(dir, 0700)
	os.WriteFile(f, []byte(fmt.Sprintf("%s\n%s\n%s\n%s\n",
		keys.serverPrivate, keys.serverPublic,
		keys.clientPrivate, keys.clientPublic)), 0600)
	log.Printf("[WG] Ключи сохранены в %s", f)
	return keys, nil
}

func setupFullConeNAT(wgIface string) error {
	log.Println("[NAT] ══════════════════════════════════════")

	os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644)

	extIface := getDefaultInterface()
	log.Printf("[NAT] Внешний: %s", extIface)

	switch {
	case commandExists("iptables"):
		for i := 0; i < 5; i++ {
			exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", wgServerCIDR, "-o", extIface, "-m", "comment", "--comment", "WDTT_MANAGED", "-j", "MASQUERADE").Run()
		}
		exec.Command("iptables", "-t", "nat", "-I", "POSTROUTING", "1", "-s", wgServerCIDR, "-o", extIface, "-m", "comment", "--comment", "WDTT_MANAGED", "-j", "MASQUERADE").Run()
		natType = "MASQUERADE iptables ✅"
		setupForwardRules(wgIface)
	case commandExists("nft"):
		setupNftNAT(extIface)
		natType = "MASQUERADE nft ✅"
		setupForwardRules(wgIface)
	default:
		natType = "NAT не настроен: нет iptables/nft"
		log.Printf("[NAT] WARNING: %s", natType)
	}

	log.Printf("[NAT] Режим: %s", natType)
	log.Println("[NAT] ══════════════════════════════════════")
	return nil
}

func setupNftNAT(extIface string) {
	exec.Command("nft", "add", "table", "ip", "wdtt").Run()
	exec.Command("nft", "add", "chain", "ip", "wdtt", "postrouting", "{ type nat hook postrouting priority 100; }").Run()
	exec.Command("nft", "add", "rule", "ip", "wdtt", "postrouting", "ip", "saddr", wgServerCIDR, "oifname", extIface, "masquerade").Run()
}

func setupForwardRules(wgIface string) {
	if commandExists("iptables") {
		for i := 0; i < 5; i++ {
			exec.Command("iptables", "-D", "FORWARD", "-i", wgIface, "-m", "comment", "--comment", "WDTT_MANAGED", "-j", "ACCEPT").Run()
			exec.Command("iptables", "-D", "FORWARD", "-o", wgIface, "-m", "comment", "--comment", "WDTT_MANAGED", "-j", "ACCEPT").Run()
		}
		exec.Command("iptables", "-A", "FORWARD", "-i", wgIface, "-m", "comment", "--comment", "WDTT_MANAGED", "-j", "ACCEPT").Run()
		exec.Command("iptables", "-A", "FORWARD", "-o", wgIface, "-m", "comment", "--comment", "WDTT_MANAGED", "-j", "ACCEPT").Run()
		return
	}
	if commandExists("nft") {
		exec.Command("nft", "add", "table", "inet", "wdtt").Run()
		exec.Command("nft", "add", "chain", "inet", "wdtt", "forward", "{ type filter hook forward priority 0; policy accept; }").Run()
		exec.Command("nft", "add", "rule", "inet", "wdtt", "forward", "iifname", wgIface, "accept").Run()
		exec.Command("nft", "add", "rule", "inet", "wdtt", "forward", "oifname", wgIface, "accept").Run()
	}
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
	bind := conn.NewDefaultBind()
	dev := device.NewDevice(tunDev, bind, logger)

	serverPrivHex, _ := b64ToHex(keys.serverPrivate)

	if err := dev.IpcSet(fmt.Sprintf(
		"private_key=%s\nlisten_port=%d\n",
		serverPrivHex, wgPort,
	)); err != nil {
		dev.Close()
		return nil, fmt.Errorf("IpcSet: %w", err)
	}

	for _, d := range db.Devices {
		pubHex, _ := b64ToHex(d.PubKey)
		if pubHex != "" {
			dev.IpcSet(fmt.Sprintf("public_key=%s\nallowed_ip=%s/32\n", pubHex, d.IP))
		}
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

func handleConn(ctx context.Context, clientConn net.Conn, wgEndpoint string, wgDev *device.Device, keys *wgKeys) {
	// Добавлен defer для предотвращения утечки сокетов при ошибках на любом этапе функции
	defer clientConn.Close()

	atomic.AddInt64(&totalConns, 1)

	var connPassword string
	var connIsMainPass bool

	dtlsConn, ok := clientConn.(*dtls.Conn)
	if !ok {
		return
	}

	hctx, hcancel := context.WithTimeout(ctx, 30*time.Second)
	if err := dtlsConn.HandshakeContext(hctx); err != nil {
		hcancel()
		return
	}
	hcancel()

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

		dbMutex.Lock()

		isMainPass := password != "" && password == db.MainPassword
		entry, isGenPass := db.Passwords[password]
		valid := isMainPass || (isGenPass && !isPasswordExpired(entry))

		if valid && isGenPass && entry.IsDeactivated {
			clientConn.Write([]byte("DENIED:deactivated"))
			log.Printf("[WG] Отказ: пароль %s деактивирован, запрос от %s", maskPassword(password), deviceID)
			dbMutex.Unlock()
		} else if valid && isGenPass && entry.DeviceID != "" && entry.DeviceID != deviceID {
			clientConn.Write([]byte("DENIED:device_mismatch"))
			log.Printf("[WG] Отказ: пароль %s привязан к %s, запрос от %s", maskPassword(password), entry.DeviceID, deviceID)
			dbMutex.Unlock()
		} else if valid {
			connPassword = password
			connIsMainPass = isMainPass

			if isGenPass && entry.DeviceID == "" {
				entry.DeviceID = deviceID
				saveDBLazy()
				log.Printf("[WG] Пароль %s привязан к устройству %s", maskPassword(password), deviceID)
			}

			dev, exists := db.Devices[deviceID]
			if !exists {
				dev = &ClientDevice{DeviceID: deviceID, IP: getNextIP()}
				privB64, pubB64, keyErr := generateKeyPair()
				if keyErr == nil && dev.IP != "" {
					dev.PrivKey = privB64
					dev.PubKey = pubB64
					db.Devices[deviceID] = dev
					saveDBLazy()
					log.Printf("[WG] Новое устройство %s (IP: %s)", deviceID, dev.IP)
				} else {
					dev = nil
				}
			}
			if dev != nil {
				upsertPeerInWG(wgDev, dev)
				clientConn.Write([]byte(buildClientConfig(keys.serverPublic, dev.PrivKey, dev.IP, clientPort)))
			} else {
				clientConn.Write([]byte("NOCONF"))
			}
			dbMutex.Unlock()
		} else {
			if isGenPass && isPasswordExpired(entry) {
				clientConn.Write([]byte("DENIED:expired"))
				log.Printf("[WG] Отказ: пароль %s истёк, от %s", maskPassword(password), deviceID)
			} else {
				clientConn.Write([]byte("DENIED:wrong_password"))
				log.Printf("[WG] Отказ (неверный пароль) от %s", deviceID)
			}
			dbMutex.Unlock()
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

	wgConn, err := net.Dial("udp", wgEndpoint)
	if err != nil {
		return
	}
	defer wgConn.Close()

	if uc, ok := wgConn.(*net.UDPConn); ok {
		uc.SetReadBuffer(2 * 1024 * 1024)
		uc.SetWriteBuffer(2 * 1024 * 1024)
	}

	if _, err := wgConn.Write(firstPacket); err != nil {
		return
	}
	atomic.AddInt64(&totalBytesFromClient, int64(len(firstPacket)))

	pctx, pcancel := context.WithCancel(ctx)
	defer pcancel()

	context.AfterFunc(pctx, func() {
		clientConn.SetDeadline(time.Now())
		wgConn.SetDeadline(time.Now())
	})

	var localUpBytes int64
	var localDownBytes int64

	flushStats := func() bool {
		up := atomic.SwapInt64(&localUpBytes, 0)
		down := atomic.SwapInt64(&localDownBytes, 0)

		dbMutex.Lock()
		defer dbMutex.Unlock()

		e, ok := db.Passwords[connPassword]
		if !ok || e == nil || isPasswordExpired(e) || e.IsDeactivated {
			return false
		}

		e.UpBytes += up
		e.DownBytes += down
		return true
	}

	var proxyWg sync.WaitGroup
	proxyWg.Add(2)

	if connPassword != "" && !connIsMainPass {
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

				localFromClient += int64(nn)
				if connPassword != "" && !connIsMainPass {
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

				localToClient += int64(nn)
				if connPassword != "" && !connIsMainPass {
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
	if connPassword != "" && !connIsMainPass {
		flushStats()
	}
}
