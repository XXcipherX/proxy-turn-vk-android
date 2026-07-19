

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
)

func resolveServerListenAddress(value string) (*net.UDPAddr, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("listen address is empty")
	}
	host, _, err := net.SplitHostPort(value)
	if err != nil {
		return nil, fmt.Errorf("parse listen address %q: %w", value, err)
	}
	if parsedHost := net.ParseIP(host); parsedHost != nil && parsedHost.To4() == nil {
		return nil, fmt.Errorf("listen address must be IPv4")
	}
	addr, err := net.ResolveUDPAddr("udp4", value)
	if err != nil {
		return nil, fmt.Errorf("resolve listen address %q: %w", value, err)
	}
	if addr.Port < 1 || addr.Port > 65535 {
		return nil, fmt.Errorf("listen port must be between 1 and 65535")
	}
	if addr.IP != nil && addr.IP.To4() == nil {
		return nil, fmt.Errorf("listen address must be IPv4")
	}
	return addr, nil
}

func validateDNSServers(value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("DNS list is empty")
	}
	for _, rawServer := range strings.Split(value, ",") {
		server := strings.TrimSpace(rawServer)
		parsed := net.ParseIP(server)
		if server == "" || parsed == nil || parsed.To4() == nil {
			return fmt.Errorf("DNS server %q must be an IPv4 address", rawServer)
		}
	}
	return nil
}

func validateTelegramCredentials(adminID, botToken string) error {
	adminID = strings.TrimSpace(adminID)
	botToken = strings.TrimSpace(botToken)
	if (adminID == "") != (botToken == "") {
		return fmt.Errorf("admin and bot-token must be configured together")
	}
	if adminID == "" {
		return nil
	}
	parsedAdminID, err := strconv.ParseInt(adminID, 10, 64)
	if err != nil || parsedAdminID <= 0 {
		return fmt.Errorf("admin must be a positive Telegram chat ID")
	}
	tokenParts := strings.SplitN(botToken, ":", 2)
	if len(botToken) > 256 || len(tokenParts) != 2 || tokenParts[0] == "" || tokenParts[1] == "" {
		return fmt.Errorf("bot-token has an invalid format")
	}
	if tokenID, err := strconv.ParseUint(tokenParts[0], 10, 64); err != nil || tokenID == 0 {
		return fmt.Errorf("bot-token has an invalid bot ID")
	}
	for i := 0; i < len(botToken); i++ {
		ch := botToken[i]
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == ':' || ch == '-' {
			continue
		}
		return fmt.Errorf("bot-token contains unsupported characters")
	}
	return nil
}

func main() {
	listen := flag.String("listen", "0.0.0.0:56000", "DTLS адрес")
	wgPort := flag.Int("wg-port", defaultInternalWGPort, "WireGuard UDP порт")
	configDir := flag.String("config-dir", "/etc/wdtt", "директория конфигурации")
	mainPass := flag.String("password", "", "пароль владельца")
	adminID := flag.String("admin", "", "Telegram Admin ID")
	botToken := flag.String("bot-token", "", "Telegram Bot Token")
	dnsFlag := flag.String("dns", dns, "DNS для клиента (можно несколько через запятую)")
	maxConnections := flag.Int("max-connections", 512, "максимум одновременных DTLS-соединений")
	handshakeRate := flag.Int("handshake-rate", 64, "максимум новых DTLS handshakes в секунду")
	flag.Parse()
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	if flag.NArg() != 0 {
		log.Fatalf("[CONFIG] неожиданные аргументы: %s", strings.Join(flag.Args(), " "))
	}
	if *maxConnections < 1 || *maxConnections > 10000 {
		log.Fatalf("[CONFIG] max-connections должен быть от 1 до 10000")
	}
	if *handshakeRate < 1 || *handshakeRate > 10000 {
		log.Fatalf("[CONFIG] handshake-rate должен быть от 1 до 10000")
	}
	if *wgPort < 1 || *wgPort > 65535 {
		log.Fatalf("[CONFIG] wg-port должен быть от 1 до 65535")
	}
	if strings.TrimSpace(*configDir) == "" {
		log.Fatalf("[CONFIG] config-dir не может быть пустым")
	}
	addr, err := resolveServerListenAddress(*listen)
	if err != nil {
		log.Fatalf("[CONFIG] %v", err)
	}
	if addr.Port == *wgPort {
		log.Fatalf("[CONFIG] listen и wg-port не могут использовать один UDP-порт")
	}
	if err := validateDNSServers(*dnsFlag); err != nil {
		log.Fatalf("[CONFIG] %v", err)
	}
	if err := validateTelegramCredentials(*adminID, *botToken); err != nil {
		log.Fatalf("[CONFIG] %v", err)
	}
	*adminID = strings.TrimSpace(*adminID)
	*botToken = strings.TrimSpace(*botToken)
	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		log.Fatalf("[DTLS] создание сертификата: %v", err)
	}
	connectionLimit := newConnectionLimiter(*maxConnections, *handshakeRate)
	identityLimit := newIdentityConnectionLimiter(*maxConnections)

	if v := strings.TrimSpace(*dnsFlag); v != "" {
		dns = v
	}

	log.Println("══════════════════════════════════════════")
	log.Println("   WDTT Server v2 (Multi-User)")
	log.Println("══════════════════════════════════════════")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sig)
	go func() {
		<-sig
		cancel()
	}()

	if err := initDB(*configDir, *mainPass, *adminID, *botToken); err != nil {
		log.Fatalf("[DB] Запуск: %v", err)
	}

	keys, err := loadOrGenerateKeys(*configDir)
	if err != nil {
		log.Fatalf("[WG] Ключи: %v", err)
	}

	wgDev, err := startUserspaceWG(keys, *wgPort)
	if err != nil {
		log.Fatalf("[WG] Запуск: %v", err)
	}
	if removed, cleanupErr := cleanupExpiredPasswords(wgDev); cleanupErr != nil {
		log.Printf("[DB] Очистка истёкших паролей при старте: %v", cleanupErr)
	} else if removed > 0 {
		log.Printf("[DB] Удалено истёкших паролей при старте: %d", removed)
	}
	if err := syncPersistedPeersToWG(wgDev); err != nil {
		log.Fatalf("[WG] Восстановление peer: %v", err)
	}
	defer func() {
		wgDev.Close()
		runCmdSilent("ip", "link", "del", wgIfaceName)
	}()

	var workers sync.WaitGroup
	workers.Add(3)
	go func() {
		defer workers.Done()
		statsLoop(ctx, *configDir)
	}()
	go func() {
		defer workers.Done()
		expiredPasswordJanitor(ctx, wgDev)
	}()
	go func() {
		defer workers.Done()
		botLoop(ctx, *botToken, *adminID, wgDev)
	}()

	if serverWrapKeys.Count() == 0 {
		log.Fatalf("[WRAP] нет активных паролей для WRAP")
	}

	wrapListener, err := listenWrapped(addr, serverWrapKeys)
	if err != nil {
		log.Fatalf("[WRAP] %v", err)
	}

	listener, err := dtls.NewListenerWithOptions(wrapListener, dtls.WithCertificates(cert), dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret), dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256), dtls.WithConnectionIDGenerator(dtls.RandomCIDGenerator(8)))
	if err != nil {
		log.Fatalf("[DTLS] %v", err)
	}
	context.AfterFunc(ctx, func() { listener.Close() })

	wgEndpoint := fmt.Sprintf("127.0.0.1:%d", *wgPort)

	log.Printf("   DTLS: %s | WG: %s | NAT: %s", *listen, wgEndpoint, natType)
	log.Printf("   WRAP: password HKDF + RTP AEAD | keys: %d", serverWrapKeys.Count())
	log.Printf("   LIMITS: connections=%d | handshakes=%d/s", *maxConnections, *handshakeRate)
	log.Printf("   TEMP LIMITS: total=%d | per-password=%d | per-IP=%d", identityLimit.maxGeneratedTotal, identityLimit.maxPerPassword, identityLimit.maxPerSourceIP)
	log.Println("[SERVER] Готов")

	for {
		dtlsConn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				workers.Wait()
				if err := flushDB(); err != nil {
					log.Printf("[DB] Финальное сохранение: %v", err)
				}
				return
			default:
			}
			continue
		}
		if !connectionLimit.TryAcquire() {
			atomic.AddInt64(&rejectedConns, 1)
			dtlsConn.Close()
			continue
		}
		workers.Add(1)
		go func(c net.Conn) {
			defer workers.Done()
			defer connectionLimit.Release()
			defer c.Close()
			handleConn(ctx, c, wrapListener, identityLimit, wgEndpoint, wgDev, keys)
		}(dtlsConn)
	}
}
