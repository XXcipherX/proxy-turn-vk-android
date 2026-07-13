package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/hkdf"

	"golang.zx2c4.com/wireguard/device"
)

func generatePassword() string {
	b := make([]byte, generatedPasswordLen)
	randomBytes := make([]byte, len(b))
	if _, err := rand.Read(randomBytes); err != nil {
		now := time.Now().UnixNano()
		for i := range b {
			b[i] = passChars[int(now+int64(i))%len(passChars)]
		}
		return string(b)
	}
	for i, raw := range randomBytes {
		b[i] = passChars[int(raw)%len(passChars)]
	}
	return string(b)
}

var publicIP string = ""

var (
	dbDirty     int32
	dbSaveTimer *time.Timer
	dbSaveMu    sync.Mutex
	dbWriteMu   sync.Mutex
)

func getPublicIP() string {
	if publicIP != "" {
		return publicIP
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://api.ipify.org")
	if err != nil {
		return "YOUR_SERVER_IP"
	}
	defer resp.Body.Close()
	ipBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "YOUR_SERVER_IP"
	}
	publicIP = string(bytes.TrimSpace(ipBytes))
	return publicIP
}

func stripVkUrl(url string) string {
	url = strings.TrimSpace(url)
	if idx := strings.LastIndex(url, "/"); idx != -1 {
		url = url[idx+1:]
	}
	if idx := strings.Index(url, "?"); idx != -1 {
		url = url[:idx]
	}
	return strings.TrimSpace(url)
}

type wrapKeyEntry struct {
	id       string
	key      []byte
	identity wrapIdentity
}

type wrapIdentity struct {
	Password string
	IsMain   bool
}

type wrapKeyStore struct {
	mu      sync.RWMutex
	entries []wrapKeyEntry
}

func newWrapKeyStore() *wrapKeyStore {
	return &wrapKeyStore{}
}

func deriveWrapKey(password string) ([]byte, error) {
	if password == "" {
		return nil, errors.New("empty password")
	}
	key := make([]byte, wrapKeyLen)
	reader := hkdf.New(
		sha256.New,
		[]byte(password),
		[]byte("WDTT-WRAP-v1"),
		[]byte("rtp-obfs/chacha20poly1305"),
	)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, fmt.Errorf("derive wrap key: %w", err)
	}
	return key, nil
}

func wrapKeyID(password string) string {
	sum := sha256.Sum256([]byte("WDTT-WRAP-ID-v1\x00" + password))
	return hex.EncodeToString(sum[:8])
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func (s *wrapKeyStore) SetPasswords(mainPassword string, generated []string) error {
	next := make([]wrapKeyEntry, 0, len(generated)+1)
	seen := make(map[string]struct{}, len(generated)+1)

	if mainPassword != "" {
		key, err := deriveWrapKey(mainPassword)
		if err != nil {
			return err
		}
		next = append(next, wrapKeyEntry{
			id:       "main",
			key:      key,
			identity: wrapIdentity{Password: mainPassword, IsMain: true},
		})
		seen["main"] = struct{}{}
	}

	for _, password := range generated {
		if password == "" {
			continue
		}
		id := "pass:" + wrapKeyID(password)
		if _, exists := seen[id]; exists {
			continue
		}
		key, err := deriveWrapKey(password)
		if err != nil {
			for _, entry := range next {
				zeroBytes(entry.key)
			}
			return err
		}
		next = append(next, wrapKeyEntry{
			id:       id,
			key:      key,
			identity: wrapIdentity{Password: password},
		})
		seen[id] = struct{}{}
	}

	s.mu.Lock()
	old := s.entries
	s.entries = next
	s.mu.Unlock()
	for _, entry := range old {
		aeadCacheMu.Lock()
		delete(aeadCache, string(entry.key))
		aeadCacheMu.Unlock()
		zeroBytes(entry.key)
	}
	return nil
}

func (s *wrapKeyStore) AddPassword(password string) error {
	key, err := deriveWrapKey(password)
	if err != nil {
		return err
	}
	id := "pass:" + wrapKeyID(password)

	s.mu.Lock()
	defer s.mu.Unlock()
	for _, entry := range s.entries {
		if entry.id == id {
			zeroBytes(key)
			return nil
		}
	}
	s.entries = append(s.entries, wrapKeyEntry{
		id:       id,
		key:      key,
		identity: wrapIdentity{Password: password},
	})
	return nil
}

func (s *wrapKeyStore) RemovePassword(password string) {
	id := "pass:" + wrapKeyID(password)

	s.mu.Lock()
	defer s.mu.Unlock()
	for i, entry := range s.entries {
		if entry.id != id {
			continue
		}
		aeadCacheMu.Lock()
		delete(aeadCache, string(entry.key))
		aeadCacheMu.Unlock()
		zeroBytes(entry.key)
		copy(s.entries[i:], s.entries[i+1:])
		s.entries[len(s.entries)-1] = wrapKeyEntry{}
		s.entries = s.entries[:len(s.entries)-1]
		return
	}
}

func (s *wrapKeyStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

func (s *wrapKeyStore) Unwrap(raw, dst []byte) ([]byte, wrapIdentity, int, error) {
	if !obfsIsRTPPacket(raw) {
		return nil, wrapIdentity{}, 0, errors.New("wrap: non-obfs packet")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.entries) == 0 {
		return nil, wrapIdentity{}, 0, errors.New("wrap: no active keys")
	}
	for _, entry := range s.entries {
		m, err := obfsUnwrapPacket(entry.key, raw, dst)
		if err == nil {
			return append([]byte(nil), entry.key...), entry.identity, m, nil
		}
	}
	return nil, wrapIdentity{}, 0, errors.New("wrap: auth failed")
}

func refreshWrapKeysFromDBLocked() error {
	passwords := make([]string, 0, len(db.Passwords))
	for password, entry := range db.Passwords {
		if !isPasswordExpired(entry) {
			passwords = append(passwords, password)
		}
	}
	return serverWrapKeys.SetPasswords(db.MainPassword, passwords)
}

func initDB(dir, mainPass, adminID, botToken string) {
	dbFile = filepath.Join(dir, "passwords.json")
	db = &Database{
		Passwords: make(map[string]*PasswordEntry),
		Devices:   make(map[string]*ClientDevice),
	}
	data, err := os.ReadFile(dbFile)
	if err == nil {
		json.Unmarshal(data, db)
	}
	if db.Passwords == nil {
		db.Passwords = make(map[string]*PasswordEntry)
	}
	if db.Devices == nil {
		db.Devices = make(map[string]*ClientDevice)
	}
	db.MainPassword = mainPass
	db.AdminID = adminID
	db.BotToken = botToken
	if err := saveDBSync(); err != nil {
		log.Printf("[DB] initial save: %v", err)
	}
	if err := refreshWrapKeysFromDBLocked(); err != nil {
		log.Fatalf("[WRAP] init keys: %v", err)
	}
}

func saveDBLazy() {
	atomic.StoreInt32(&dbDirty, 1)

	dbSaveMu.Lock()
	if dbSaveTimer == nil {
		dbSaveTimer = time.AfterFunc(5*time.Second, func() {
			dbSaveMu.Lock()
			dbSaveTimer = nil
			dbSaveMu.Unlock()

			if atomic.SwapInt32(&dbDirty, 0) == 1 {
				if err := saveDBSync(); err != nil {
					log.Printf("[DB] delayed save: %v", err)
				}
			}
		})
	}
	dbSaveMu.Unlock()
}

func flushDB() {
	dbSaveMu.Lock()
	timer := dbSaveTimer
	dbSaveTimer = nil
	dbSaveMu.Unlock()
	if timer != nil {
		timer.Stop()
	}
	atomic.StoreInt32(&dbDirty, 0)
	if err := saveDBSync(); err != nil {
		log.Printf("[DB] final save: %v", err)
	}
}

func saveDBSync() error {
	dbWriteMu.Lock()
	defer dbWriteMu.Unlock()

	dbMutex.RLock()
	data, err := json.Marshal(db)
	dbMutex.RUnlock()
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	tmp := dbFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := os.Rename(tmp, dbFile); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replace database: %w", err)
	}
	return nil
}

func isPasswordExpired(entry *PasswordEntry) bool {
	if entry == nil {
		return true
	}
	if entry.ExpiresAt == 0 {
		return false
	}
	return time.Now().Unix() > entry.ExpiresAt
}

func getNextIP() string {
	used := make(map[string]bool)
	for _, dev := range db.Devices {
		used[dev.IP] = true
	}
	for i := 2; i <= 250; i++ {
		ip := fmt.Sprintf("10.66.66.%d", i)
		if !used[ip] {
			return ip
		}
	}
	return ""
}

func botLoop(token string, adminIDstr string, wgDev *device.Device) {
	if token == "" || adminIDstr == "" {
		return
	}
	adminID, _ := strconv.ParseInt(adminIDstr, 10, 64)
	if adminID == 0 {
		return
	}

	go func() {
		cmds := `{"commands":[{"command":"start","description":"Главное меню"},{"command":"new","description":"Создать временный пароль"},{"command":"list","description":"Управление доступами"}]}`
		resp, err := http.Post(fmt.Sprintf("https://api.telegram.org/bot%s/setMyCommands", token), "application/json", strings.NewReader(cmds))
		if err == nil {
			resp.Body.Close()
		}
	}()

	offset := 0
	client := &http.Client{Timeout: 65 * time.Second}

	var waitingForDays bool
	var waitingForPorts bool
	var waitingForHash bool
	var targetPassword string

	var tempDays int
	var tempPorts string

	for {
		url := fmt.Sprintf("https://api.telegram.org/bot%s/getUpdates?timeout=60&offset=%d", token, offset)
		resp, err := client.Get(url)
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}

		var res struct {
			Ok     bool `json:"ok"`
			Result []struct {
				UpdateID int `json:"update_id"`
				Message  *struct {
					Chat struct {
						ID int64 `json:"id"`
					} `json:"chat"`
					Text string `json:"text"`
				} `json:"message"`
				CallbackQuery *struct {
					ID      string `json:"id"`
					Data    string `json:"data"`
					Message struct {
						MessageID int `json:"message_id"`
						Chat      struct {
							ID int64 `json:"id"`
						} `json:"chat"`
					} `json:"message"`
				} `json:"callback_query"`
			} `json:"result"`
		}

		err = json.NewDecoder(resp.Body).Decode(&res)
		resp.Body.Close()
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}

		for _, u := range res.Result {
			offset = u.UpdateID + 1

			if u.CallbackQuery != nil && u.CallbackQuery.Message.Chat.ID == adminID {
				data := u.CallbackQuery.Data
				answerCallback(token, u.CallbackQuery.ID)

				if strings.HasPrefix(data, "viewpass_") {

					pass := strings.TrimPrefix(data, "viewpass_")
					dbMutex.Lock()
					entry, exists := db.Passwords[pass]
					if !exists || entry == nil {
						dbMutex.Unlock()
						sendTelegram(token, adminID, "❌ Пароль не найден", nil)
						continue
					}
					txt := fmt.Sprintf("🔑 *Пароль:* `%s`\n", pass)
					if entry.VkHash != "" {
						pts := strings.Split(entry.Ports, ",")
						if len(pts) < 3 {
							pts = []string{"56000", "56001", "9000"}
						}
						srvIP := getPublicIP()
						link := fmt.Sprintf("wdtt://%s:%s:%s:%s:%s:%s", srvIP, pts[0], pts[1], pts[2], pass, entry.VkHash)
						txt += fmt.Sprintf("🔗 *Быстрая ссылка:* `%s`\n", link)
					}
					if entry.IsDeactivated {
						txt += "🔴 Статус: *ДЕАКТИВИРОВАН*\n"
					} else {
						txt += "🟢 Статус: *АКТИВЕН*\n"
					}

					if entry.ExpiresAt > 0 {
						expireTime := time.Unix(entry.ExpiresAt, 0)
						remaining := time.Until(expireTime)
						if remaining > 0 {
							txt += fmt.Sprintf("⏰ Истекает: %s (через %dd)\n", expireTime.Format("02.01.2006"), int(remaining.Hours()/24))
						} else {
							txt += "⏰ *ИСТЁК* ❌\n"
						}
					} else {
						txt += "⏰ Бессрочный ♾\n"
					}

					txt += fmt.Sprintf("\n📊 *Трафик:*\n• Скачано: %.2f MB\n• Отдано: %.2f MB\n", float64(entry.DownBytes)/(1024*1024), float64(entry.UpBytes)/(1024*1024))
					txt += "\n📱 *Привязанное устройство:*\n"
					var kb []map[string]interface{}
					if entry.DeviceID == "" {
						txt += "_Ожидает первого подключения..._\n"
					} else {
						dev, devExists := db.Devices[entry.DeviceID]
						if devExists {
							txt += fmt.Sprintf("• ID: `%s`\n• IP: `%s`\n", entry.DeviceID, dev.IP)
						} else {
							txt += fmt.Sprintf("• ID: `%s` (устройство удалено)\n", entry.DeviceID)
						}
						kb = append(kb, map[string]interface{}{
							"text":          "🗑 Отвязать устройство",
							"callback_data": "unbind_" + pass,
						})
					}
					dbMutex.Unlock()
					if entry.IsDeactivated {
						kb = append(kb, map[string]interface{}{
							"text":          "✅ Активировать",
							"callback_data": "react_" + pass,
						})
					} else {
						kb = append(kb, map[string]interface{}{
							"text":          "⏸ Деактивировать",
							"callback_data": "deact_" + pass,
						})
					}
					kb = append(kb, map[string]interface{}{
						"text":          "❌ Удалить пароль",
						"callback_data": "delpass_" + pass,
					})
					kb = append(kb, map[string]interface{}{
						"text":          "◀️ Назад к списку",
						"callback_data": "backlist",
					})
					var keyboard [][]map[string]interface{}
					for _, btn := range kb {
						keyboard = append(keyboard, []map[string]interface{}{btn})
					}
					sendTelegram(token, adminID, txt, map[string]interface{}{"inline_keyboard": keyboard})

				} else if strings.HasPrefix(data, "deact_") {
					pass := strings.TrimPrefix(data, "deact_")
					dbMutex.Lock()
					entry, exists := db.Passwords[pass]
					if exists && entry != nil {
						entry.IsDeactivated = true

						if entry.DeviceID != "" {
							if dev, devExists := db.Devices[entry.DeviceID]; devExists {
								if pubHex, err := b64ToHex(dev.PubKey); err == nil && pubHex != "" {
									wgDev.IpcSet(fmt.Sprintf("public_key=%s\nremove=true\n", pubHex))
								}
							}
						}
						saveDBLazy()
					}
					dbMutex.Unlock()
					sendTelegram(token, adminID, fmt.Sprintf("⏸ Пароль `%s` деактивирован", pass), nil)

				} else if strings.HasPrefix(data, "react_") {
					pass := strings.TrimPrefix(data, "react_")
					dbMutex.Lock()
					entry, exists := db.Passwords[pass]
					if exists && entry != nil {
						entry.IsDeactivated = false
						saveDBLazy()
					}
					dbMutex.Unlock()
					sendTelegram(token, adminID, fmt.Sprintf("✅ Пароль `%s` активирован", pass), nil)

				} else if data == "mainlink" {
					targetPassword = "main"
					var keyboard [][]map[string]interface{}
					keyboard = append(keyboard, []map[string]interface{}{
						{"text": "Да", "callback_data": "ports_def"},
						{"text": "Нет", "callback_data": "ports_custom"},
					})
					sendTelegram(token, adminID, "⚙️ Использовать стандартные порты для главного пароля (56000, 56001, 9000)?", map[string]interface{}{"inline_keyboard": keyboard})

				} else if strings.HasPrefix(data, "unbind_") {
					pass := strings.TrimPrefix(data, "unbind_")
					dbMutex.Lock()
					entry, exists := db.Passwords[pass]
					if exists && entry != nil && entry.DeviceID != "" {

						dev, devExists := db.Devices[entry.DeviceID]
						if devExists {
							pubHex, _ := b64ToHex(dev.PubKey)
							wgDev.IpcSet(fmt.Sprintf("public_key=%s\nremove=true\n", pubHex))
							delete(db.Devices, entry.DeviceID)
						}
						entry.DeviceID = ""
						saveDBLazy()
					}
					dbMutex.Unlock()
					sendTelegram(token, adminID, fmt.Sprintf("✅ Устройство отвязано от пароля `%s`", pass), nil)

				} else if strings.HasPrefix(data, "delpass_") {
					pass := strings.TrimPrefix(data, "delpass_")
					dbMutex.Lock()
					entry, exists := db.Passwords[pass]
					if exists && entry != nil && entry.DeviceID != "" {
						dev, devExists := db.Devices[entry.DeviceID]
						if devExists {
							pubHex, _ := b64ToHex(dev.PubKey)
							wgDev.IpcSet(fmt.Sprintf("public_key=%s\nremove=true\n", pubHex))
							delete(db.Devices, entry.DeviceID)
						}
					}
					delete(db.Passwords, pass)
					serverWrapKeys.RemovePassword(pass)
					saveDBLazy()
					dbMutex.Unlock()
					sendTelegram(token, adminID, fmt.Sprintf("✅ Пароль `%s` и его устройство удалены", pass), nil)

				} else if strings.HasPrefix(data, "deldev_") {
					devID := strings.TrimPrefix(data, "deldev_")
					dbMutex.Lock()
					dev, exists := db.Devices[devID]
					if exists {
						delete(db.Devices, devID)
						pubHex, _ := b64ToHex(dev.PubKey)
						wgDev.IpcSet(fmt.Sprintf("public_key=%s\nremove=true\n", pubHex))

						for _, entry := range db.Passwords {
							if entry != nil && entry.DeviceID == devID {
								entry.DeviceID = ""
							}
						}
						saveDBLazy()
					}
					dbMutex.Unlock()
					sendTelegram(token, adminID, fmt.Sprintf("✅ Устройство `%s` удалено", devID), nil)

				} else if data == "backlist" {
					sendPasswordList(token, adminID, wgDev)
				} else if data == "ports_def" {
					tempPorts = "56000,56001,9000"
					waitingForHash = true
					sendTelegram(token, adminID, "🔑 Укажите VK хеш (или несколько через запятую):", nil)
				} else if data == "ports_custom" {
					waitingForPorts = true
					sendTelegram(token, adminID, "⚙️ Укажите через запятую 3 порта (DTLS,WG,TUN):\nНапример: 56000,56001,9000", nil)
				}
			}

			msg := u.Message
			if msg == nil || msg.Chat.ID != adminID {
				continue
			}

			cmd := strings.TrimSpace(msg.Text)

			if waitingForDays {
				waitingForDays = false
				days, parseErr := strconv.Atoi(cmd)
				if parseErr != nil || days < 1 || days > 365 {
					sendTelegram(token, adminID, "❌ Неверное значение. Укажите число от 1 до 365, или отправьте /new заново.", nil)
					continue
				}
				tempDays = days

				var keyboard [][]map[string]interface{}
				keyboard = append(keyboard, []map[string]interface{}{
					{"text": "Да", "callback_data": "ports_def"},
					{"text": "Нет", "callback_data": "ports_custom"},
				})
				sendTelegram(token, adminID, "⚙️ Использовать стандартные порты (56000, 56001, 9000)?", map[string]interface{}{"inline_keyboard": keyboard})
				continue
			}

			if waitingForPorts {
				parts := strings.Split(cmd, ",")
				if len(parts) != 3 {
					sendTelegram(token, adminID, "❌ Неверный формат. Укажите 3 порта через запятую (например: 56000,56001,9000):", nil)
					continue
				}
				p1 := strings.TrimSpace(parts[0])
				p2 := strings.TrimSpace(parts[1])
				p3 := strings.TrimSpace(parts[2])

				if _, err := strconv.Atoi(p1); err != nil {
					sendTelegram(token, adminID, "❌ Неверный порт. Повторите ввод:", nil)
					continue
				}
				if _, err := strconv.Atoi(p2); err != nil {
					sendTelegram(token, adminID, "❌ Неверный порт. Повторите ввод:", nil)
					continue
				}
				if _, err := strconv.Atoi(p3); err != nil {
					sendTelegram(token, adminID, "❌ Неверный порт. Повторите ввод:", nil)
					continue
				}

				waitingForPorts = false
				tempPorts = fmt.Sprintf("%s,%s,%s", p1, p2, p3)
				waitingForHash = true
				sendTelegram(token, adminID, "🔑 Укажите VK хеш (или несколько через запятую):", nil)
				continue
			}

			if waitingForHash {
				hash := strings.ReplaceAll(cmd, " ", "")
				if strings.Contains(hash, "http") || strings.Contains(hash, "/") {
					sendTelegram(token, adminID, "❌ Пожалуйста, отправьте только хеш (или несколько хешей через запятую). Ссылки не поддерживаются.", nil)
					continue
				}
				if hash == "" {
					sendTelegram(token, adminID, "❌ Хеш не должен быть пустым.", nil)
					continue
				}
				waitingForHash = false

				if targetPassword == "main" {
					targetPassword = ""
					srvIP := getPublicIP()
					pts := strings.Split(tempPorts, ",")
					link := fmt.Sprintf("wdtt://%s:%s:%s:%s:%s:%s", srvIP, pts[0], pts[1], pts[2], db.MainPassword, hash)
					sendTelegram(token, adminID, fmt.Sprintf("🔗 *Ссылка для главного пароля:*\n`%s`", link), nil)
					continue
				}

				dbMutex.Lock()
				if cleanupExpiredPasswordsLocked(wgDev) > 0 {
					saveDBLazy()
				}
				if len(db.Passwords) >= maxGeneratedPasswords {
					dbMutex.Unlock()
					sendTelegram(token, adminID, fmt.Sprintf("❌ Лимит паролей: максимум %d активных. Удалите ненужный пароль через /list.", maxGeneratedPasswords), nil)
					continue
				}
				newPass := ""
				for i := 0; i < 10; i++ {
					candidate := generatePassword()
					if _, exists := db.Passwords[candidate]; !exists {
						newPass = candidate
						break
					}
				}
				if newPass == "" {
					dbMutex.Unlock()
					sendTelegram(token, adminID, "❌ Не удалось создать уникальный пароль. Повторите /new.", nil)
					continue
				}
				if err := serverWrapKeys.AddPassword(newPass); err != nil {
					dbMutex.Unlock()
					sendTelegram(token, adminID, "❌ Не удалось создать WRAP-ключ для пароля. Повторите /new.", nil)
					continue
				}
				expiresAt := time.Now().Add(time.Duration(tempDays) * 24 * time.Hour).Unix()
				db.Passwords[newPass] = &PasswordEntry{
					ExpiresAt: expiresAt,
					VkHash:    hash,
					Ports:     tempPorts,
				}
				saveDBLazy()
				dbMutex.Unlock()

				expDate := time.Unix(expiresAt, 0).Format("02.01.2006")
				srvIP := getPublicIP()
				pts := strings.Split(tempPorts, ",")
				link := fmt.Sprintf("wdtt://%s:%s:%s:%s:%s:%s", srvIP, pts[0], pts[1], pts[2], newPass, hash)

				sendTelegram(token, adminID, fmt.Sprintf("🔑 Новый пароль:\n`%s`\n\n⏰ Действует %d дн. (до %s)\n📱 Ожидает первого подключения\n\n🔗 *Быстрая ссылка:* `%s`", newPass, tempDays, expDate, link), nil)
				continue
			}

			if cmd == "/start" || cmd == "/help" {
				sendTelegram(token, adminID, "🤖 *WDTT VPN Manager*\n\n/new — Создать пароль\n/list — Список паролей", nil)

			} else if cmd == "/new" {
				dbMutex.Lock()
				if cleanupExpiredPasswordsLocked(wgDev) > 0 {
					saveDBLazy()
				}
				if len(db.Passwords) >= maxGeneratedPasswords {
					dbMutex.Unlock()
					sendTelegram(token, adminID, fmt.Sprintf("❌ Лимит паролей: максимум %d активных. Удалите ненужный пароль через /list.", maxGeneratedPasswords), nil)
					continue
				}
				dbMutex.Unlock()
				waitingForDays = true
				sendTelegram(token, adminID, "📅 Введите срок действия пароля в днях (1–365):\n\n_Примеры: 30 = месяц, 365 = год_", nil)

			} else if cmd == "/list" {
				sendPasswordList(token, adminID, wgDev)
			}
		}
	}
}

func removePeerFromWG(wgDev *device.Device, dev *ClientDevice) {
	if wgDev == nil || dev == nil || dev.PubKey == "" {
		return
	}
	pubHex, err := b64ToHex(dev.PubKey)
	if err != nil {
		return
	}
	wgDev.IpcSet(fmt.Sprintf("public_key=%s\nremove=true\n", pubHex))
}

func upsertPeerInWG(wgDev *device.Device, dev *ClientDevice) {
	if wgDev == nil || dev == nil || dev.PubKey == "" || dev.IP == "" {
		return
	}
	pubHex, err := b64ToHex(dev.PubKey)
	if err != nil {
		return
	}
	wgDev.IpcSet(fmt.Sprintf("public_key=%s\nallowed_ip=%s/32\n", pubHex, dev.IP))
}

func cleanupExpiredPasswordsLocked(wgDev *device.Device) int {
	removed := 0
	for p, entry := range db.Passwords {
		if isPasswordExpired(entry) {
			if entry != nil && entry.DeviceID != "" {
				removePeerFromWG(wgDev, db.Devices[entry.DeviceID])
				delete(db.Devices, entry.DeviceID)
			}
			delete(db.Passwords, p)
			serverWrapKeys.RemovePassword(p)
			removed++
		}
	}
	return removed
}

func cleanupExpiredPasswords(wgDev *device.Device) int {
	dbMutex.Lock()
	defer dbMutex.Unlock()
	removed := cleanupExpiredPasswordsLocked(wgDev)
	if removed > 0 {
		saveDBLazy()
	}
	return removed
}

func expiredPasswordJanitor(ctx context.Context, wgDev *device.Device) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if removed := cleanupExpiredPasswords(wgDev); removed > 0 {
				log.Printf("[DB] Удалено истёкших паролей: %d", removed)
			}
		}
	}
}

func syncPersistedPeersToWG(wgDev *device.Device) {
	dbMutex.Lock()
	defer dbMutex.Unlock()
	count := 0
	for _, dev := range db.Devices {
		upsertPeerInWG(wgDev, dev)
		count++
	}
	if count > 0 {
		log.Printf("[WG] Восстановлено сохранённых устройств: %d", count)
	}
}

func sendPasswordList(token string, adminID int64, wgDev *device.Device) {
	dbMutex.Lock()
	defer dbMutex.Unlock()

	if cleanupExpiredPasswordsLocked(wgDev) > 0 {
		saveDBLazy()
	}

	txt := "🔐 *Пароли:*\n\n"
	txt += fmt.Sprintf("🔒 Главный: `%s` (владелец)\n\n", db.MainPassword)

	var inlineKb []map[string]interface{}
	inlineKb = append(inlineKb, map[string]interface{}{
		"text":          "🔗 Ссылка на главный пароль",
		"callback_data": "mainlink",
	})

	if len(db.Passwords) == 0 {
		txt += "_Нет сгенерированных паролей._\n"
	} else {
		txt += fmt.Sprintf("_Активно: %d/%d_\n\n", len(db.Passwords), maxGeneratedPasswords)
		for p, entry := range db.Passwords {
			status := "🟢"
			if entry.DeviceID != "" {
				status = "🔗"
			}
			expiry := "♾"
			if entry.ExpiresAt > 0 {
				remaining := time.Until(time.Unix(entry.ExpiresAt, 0))
				if remaining > 0 {
					expiry = fmt.Sprintf("%dd", int(remaining.Hours()/24)+1)
				} else {
					expiry = "❌"
				}
			}
			txt += fmt.Sprintf("%s `%s` (%s)\n", status, p, expiry)
			inlineKb = append(inlineKb, map[string]interface{}{
				"text":          "🔍 " + p,
				"callback_data": "viewpass_" + p,
			})
		}
	}

	txt += "\n🟢 = свободен | 🔗 = привязан"

	var replyMarkup interface{}
	if len(inlineKb) > 0 {
		var keyboard [][]map[string]interface{}
		for _, btn := range inlineKb {
			keyboard = append(keyboard, []map[string]interface{}{btn})
		}
		replyMarkup = map[string]interface{}{"inline_keyboard": keyboard}
	}
	sendTelegram(token, adminID, txt, replyMarkup)
}

func answerCallback(token, callbackID string) {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/answerCallbackQuery", token)
	payload := map[string]interface{}{"callback_query_id": callbackID}
	body, _ := json.Marshal(payload)
	http.Post(url, "application/json", bytes.NewBuffer(body))
}

func maskPassword(pass string) string {
	if len(pass) <= 3 {
		return pass
	}
	return pass[:3] + "****"
}

func sendTelegram(token string, chatID int64, text string, replyMarkup interface{}) {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)
	payload := map[string]interface{}{
		"chat_id":    chatID,
		"text":       text,
		"parse_mode": "Markdown",
	}
	if replyMarkup != nil {
		payload["reply_markup"] = replyMarkup
	}
	body, _ := json.Marshal(payload)
	http.Post(url, "application/json", bytes.NewBuffer(body))
}
