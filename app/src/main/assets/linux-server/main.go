

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
)

func main() {
	listen := flag.String("listen", "0.0.0.0:56000", "DTLS адрес")
	wgPort := flag.Int("wg-port", defaultInternalWGPort, "WireGuard UDP порт")
	configDir := flag.String("config-dir", "/etc/wdtt", "директория конфигурации")
	mainPass := flag.String("password", "", "пароль владельца")
	adminID := flag.String("admin", "", "Telegram Admin ID")
	botToken := flag.String("bot-token", "", "Telegram Bot Token")
	dnsFlag := flag.String("dns", dns, "DNS для клиента (можно несколько через запятую)")
	flag.Parse()

	if v := strings.TrimSpace(*dnsFlag); v != "" {
		dns = v
	}

	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
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

	enableBBR()

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

	addr, _ := net.ResolveUDPAddr("udp", *listen)
	cert, _ := selfsign.GenerateSelfSigned()
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
		workers.Add(1)
		go func(c net.Conn) {
			defer workers.Done()
			defer c.Close()
			handleConn(ctx, c, wrapListener, wgEndpoint, wgDev, keys)
		}(dtlsConn)
	}
}
