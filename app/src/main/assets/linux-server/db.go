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
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/hkdf"

	"golang.zx2c4.com/wireguard/device"
)

func generatePasswordFrom(reader io.Reader) (string, error) {
	password := make([]byte, generatedPasswordLen)
	randomBytes := make([]byte, 32)
	// Discard the tail of the byte range so every character has exactly the
	// same probability. This also lets us fail closed if the OS CSPRNG fails.
	cutoff := 256 - 256%len(passChars)
	for written := 0; written < len(password); {
		if _, err := io.ReadFull(reader, randomBytes); err != nil {
			return "", fmt.Errorf("generate password: %w", err)
		}
		for _, raw := range randomBytes {
			if int(raw) >= cutoff {
				continue
			}
			password[written] = passChars[int(raw)%len(passChars)]
			written++
			if written == len(password) {
				break
			}
		}
	}
	return string(password), nil
}

func generatePassword() (string, error) {
	return generatePasswordFrom(rand.Reader)
}

func validateMainPassword(password string) error {
	if len(password) < 16 {
		return errors.New("main password must contain at least 16 characters")
	}
	if len(password) > 128 {
		return errors.New("main password must contain at most 128 characters")
	}

	distinct := make(map[byte]struct{}, len(password))
	classes := 0
	hasLower, hasUpper, hasDigit, hasSymbol := false, false, false, false
	for i := 0; i < len(password); i++ {
		ch := password[i]
		distinct[ch] = struct{}{}
		switch {
		case ch >= 'a' && ch <= 'z':
			hasLower = true
		case ch >= 'A' && ch <= 'Z':
			hasUpper = true
		case ch >= '0' && ch <= '9':
			hasDigit = true
		case ch == '.' || ch == '_' || ch == '-':
			hasSymbol = true
		default:
			return errors.New("main password may contain only A-Z, a-z, 0-9, dot, underscore and dash")
		}
	}
	for _, present := range []bool{hasLower, hasUpper, hasDigit, hasSymbol} {
		if present {
			classes++
		}
	}
	if classes < 2 || len(distinct) < 8 {
		return errors.New("main password is too predictable; use a randomly generated password")
	}
	lower := strings.ToLower(password)
	for _, weak := range []string{"password", "changeme", "qwerty", "letmein", "123456", "adminadmin"} {
		if strings.Contains(lower, weak) {
			return errors.New("main password contains a common weak pattern; use a randomly generated password")
		}
	}
	return nil
}

var publicIPCache struct {
	sync.RWMutex
	value string
}

var (
	publicIPHTTPClient = &http.Client{Timeout: 5 * time.Second}
	publicIPServiceURL = "https://api.ipify.org"
)

var (
	dbRevision       atomic.Uint64
	dbSavedRevision  atomic.Uint64
	dbSaveTimer      *time.Timer
	dbSaveMu         sync.Mutex
	dbSaveInProgress bool
	dbSaveFailures   int
	dbWriteMu        sync.Mutex
	peerMutationMu   sync.Mutex
	persistDatabase  = saveDBSync
)

var (
	dbSaveDelay         = 5 * time.Second
	dbSaveRetryMinDelay = 5 * time.Second
	dbSaveRetryMaxDelay = time.Minute
)

func getPublicIP() string {
	publicIPCache.RLock()
	cached := publicIPCache.value
	publicIPCache.RUnlock()
	if cached != "" {
		return cached
	}
	resp, err := publicIPHTTPClient.Get(publicIPServiceURL)
	if err != nil {
		return "YOUR_SERVER_IP"
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return "YOUR_SERVER_IP"
	}
	ipBytes, err := io.ReadAll(io.LimitReader(resp.Body, 65))
	if err != nil || len(ipBytes) > 64 {
		return "YOUR_SERVER_IP"
	}
	parsed := net.ParseIP(strings.TrimSpace(string(ipBytes)))
	if parsed == nil || parsed.To4() == nil || !parsed.IsGlobalUnicast() || parsed.IsPrivate() || parsed.IsLoopback() {
		return "YOUR_SERVER_IP"
	}
	publicIPCache.Lock()
	if publicIPCache.value == "" {
		publicIPCache.value = parsed.To4().String()
	}
	cached = publicIPCache.value
	publicIPCache.Unlock()
	return cached
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

type passwordAccessState struct {
	active    atomic.Bool
	expiresAt atomic.Int64
}

func (s *passwordAccessState) IsActive() bool {
	if s == nil || !s.active.Load() {
		return false
	}
	expiresAt := s.expiresAt.Load()
	return expiresAt == 0 || time.Now().Unix() <= expiresAt
}

var passwordAccessStates sync.Map

func passwordAccessStateKey(password string, isMain bool) string {
	if isMain {
		return "main\x00" + password
	}
	return "generated\x00" + password
}

func setPasswordAccessState(password string, isMain bool, active bool, expiresAt int64) *passwordAccessState {
	key := passwordAccessStateKey(password, isMain)
	value, _ := passwordAccessStates.LoadOrStore(key, &passwordAccessState{})
	state := value.(*passwordAccessState)
	state.expiresAt.Store(expiresAt)
	state.active.Store(active)
	return state
}

func getPasswordAccessState(password string, isMain bool) *passwordAccessState {
	value, ok := passwordAccessStates.Load(passwordAccessStateKey(password, isMain))
	if !ok {
		return nil
	}
	return value.(*passwordAccessState)
}

func disablePasswordAccessState(password string, isMain bool) {
	if state := getPasswordAccessState(password, isMain); state != nil {
		state.active.Store(false)
	}
}

func rebuildPasswordAccessStatesLocked() {
	passwordAccessStates.Range(func(key, value interface{}) bool {
		value.(*passwordAccessState).active.Store(false)
		passwordAccessStates.Delete(key)
		return true
	})
	setPasswordAccessState(db.MainPassword, true, true, 0)
	for password, entry := range db.Passwords {
		if entry == nil {
			continue
		}
		setPasswordAccessState(password, false, !entry.IsDeactivated && !isPasswordExpired(entry), entry.ExpiresAt)
	}
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

func deviceCallbackToken(deviceID string) string {
	sum := sha256.Sum256([]byte("WDTT-DEVICE-CALLBACK-v1\x00" + deviceID))
	return hex.EncodeToString(sum[:8])
}

func mainDeviceIDs(database *Database) []string {
	boundToGeneratedPassword := make(map[string]struct{}, len(database.Passwords))
	for _, entry := range database.Passwords {
		if entry != nil && entry.DeviceID != "" {
			boundToGeneratedPassword[entry.DeviceID] = struct{}{}
		}
	}

	ids := make([]string, 0, len(database.Devices))
	for deviceID, dev := range database.Devices {
		if dev == nil {
			continue
		}
		if _, generated := boundToGeneratedPassword[deviceID]; !generated {
			ids = append(ids, deviceID)
		}
	}
	sort.Strings(ids)
	return ids
}

func findMainDeviceByCallbackToken(database *Database, token string) (string, *ClientDevice, bool) {
	var foundID string
	var foundDevice *ClientDevice
	for _, deviceID := range mainDeviceIDs(database) {
		if deviceCallbackToken(deviceID) != token {
			continue
		}
		// Treat even a theoretical truncated-hash collision as an invalid
		// callback rather than deleting an arbitrary device.
		if foundDevice != nil {
			return "", nil, false
		}
		foundID = deviceID
		foundDevice = database.Devices[deviceID]
	}
	return foundID, foundDevice, foundDevice != nil
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

func initDB(dir, mainPass, adminID, botToken string) error {
	if err := validateMainPassword(mainPass); err != nil {
		return fmt.Errorf("invalid main password: %w", err)
	}
	dbFile = filepath.Join(dir, "passwords.json")
	loaded := &Database{
		Passwords: make(map[string]*PasswordEntry),
		Devices:   make(map[string]*ClientDevice),
	}
	data, err := os.ReadFile(dbFile)
	if err == nil {
		if len(bytes.TrimSpace(data)) == 0 {
			return fmt.Errorf("database %s is empty", dbFile)
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(loaded); err != nil {
			return fmt.Errorf("decode database %s: %w", dbFile, err)
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return fmt.Errorf("decode database %s: trailing JSON data", dbFile)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read database %s: %w", dbFile, err)
	}
	if loaded.Passwords == nil {
		loaded.Passwords = make(map[string]*PasswordEntry)
	}
	if loaded.Devices == nil {
		loaded.Devices = make(map[string]*ClientDevice)
	}
	if err := validatePersistentDatabase(loaded); err != nil {
		return fmt.Errorf("validate database %s: %w", dbFile, err)
	}
	loaded.MainPassword = mainPass
	loaded.AdminID = adminID
	loaded.BotToken = botToken
	db = loaded
	if err := saveDBSync(); err != nil {
		return fmt.Errorf("initial database save: %w", err)
	}
	dbSaveMu.Lock()
	if dbSaveTimer != nil {
		dbSaveTimer.Stop()
		dbSaveTimer = nil
	}
	dbSaveInProgress = false
	dbSaveFailures = 0
	dbRevision.Store(0)
	dbSavedRevision.Store(0)
	dbSaveMu.Unlock()
	if err := refreshWrapKeysFromDBLocked(); err != nil {
		return fmt.Errorf("initialize WRAP keys: %w", err)
	}
	rebuildPasswordAccessStatesLocked()
	return nil
}

func validateDeviceID(deviceID string) error {
	if len(deviceID) == 0 || len(deviceID) > 128 {
		return errors.New("device ID must contain 1 to 128 characters")
	}
	for i := 0; i < len(deviceID); i++ {
		ch := deviceID[i]
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == ':' || ch == '-' {
			continue
		}
		return fmt.Errorf("device ID contains unsupported byte 0x%02x", ch)
	}
	return nil
}

func validateStoredPassword(password string) error {
	if len(password) == 0 || len(password) > 128 {
		return errors.New("password key must contain 1 to 128 characters")
	}
	for i := 0; i < len(password); i++ {
		ch := password[i]
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == '-' {
			continue
		}
		return fmt.Errorf("password key contains unsupported byte 0x%02x", ch)
	}
	return nil
}

func parsePortTriplet(ports string) (string, error) {
	parts := strings.Split(ports, ",")
	if len(parts) != 3 {
		return "", errors.New("ports must contain exactly three comma-separated values")
	}
	parsed := make([]string, 0, 3)
	seen := make(map[int]struct{}, 3)
	for _, rawPort := range parts {
		port, err := strconv.Atoi(strings.TrimSpace(rawPort))
		if err != nil || port < 1 || port > 65535 {
			return "", fmt.Errorf("invalid port %q", rawPort)
		}
		if _, exists := seen[port]; exists {
			return "", fmt.Errorf("port %d is duplicated", port)
		}
		seen[port] = struct{}{}
		parsed = append(parsed, strconv.Itoa(port))
	}
	return strings.Join(parsed, ","), nil
}

func validateStoredPorts(ports string) error {
	if ports == "" {
		return nil
	}
	_, err := parsePortTriplet(ports)
	return err
}

func validateStoredVKHash(hash string) error {
	if len(hash) > 2048 {
		return errors.New("VK hash is too long")
	}
	for i := 0; i < len(hash); i++ {
		ch := hash[i]
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == ',' || ch == '-' {
			continue
		}
		return fmt.Errorf("VK hash contains unsupported byte 0x%02x", ch)
	}
	return nil
}

func validatePersistentDatabase(database *Database) error {
	if database == nil {
		return errors.New("database is nil")
	}
	if len(database.Passwords) > maxGeneratedPasswords {
		return fmt.Errorf("password count %d exceeds limit %d", len(database.Passwords), maxGeneratedPasswords)
	}
	if len(database.Devices) > 249 {
		return fmt.Errorf("device count %d exceeds address pool", len(database.Devices))
	}

	boundDevices := make(map[string]string, len(database.Passwords))
	for password, entry := range database.Passwords {
		if err := validateStoredPassword(password); err != nil {
			return fmt.Errorf("password %q: %w", maskPassword(password), err)
		}
		if entry == nil {
			return fmt.Errorf("password %s has a null entry", maskPassword(password))
		}
		if entry.ExpiresAt < 0 {
			return fmt.Errorf("password %s has a negative expiry", maskPassword(password))
		}
		if err := validateStoredPorts(entry.Ports); err != nil {
			return fmt.Errorf("password %s: %w", maskPassword(password), err)
		}
		if err := validateStoredVKHash(entry.VkHash); err != nil {
			return fmt.Errorf("password %s: %w", maskPassword(password), err)
		}
		if entry.DeviceID == "" {
			continue
		}
		if err := validateDeviceID(entry.DeviceID); err != nil {
			return fmt.Errorf("password %s device: %w", maskPassword(password), err)
		}
		if previous, exists := boundDevices[entry.DeviceID]; exists {
			return fmt.Errorf("device %q is bound to both %s and %s", entry.DeviceID, maskPassword(previous), maskPassword(password))
		}
		if database.Devices[entry.DeviceID] == nil {
			return fmt.Errorf("password %s references missing device %q", maskPassword(password), entry.DeviceID)
		}
		boundDevices[entry.DeviceID] = password
	}

	usedIPs := make(map[string]string, len(database.Devices))
	usedPublicKeys := make(map[string]string, len(database.Devices))
	for deviceID, dev := range database.Devices {
		if err := validateDeviceID(deviceID); err != nil {
			return fmt.Errorf("device map key %q: %w", deviceID, err)
		}
		if dev == nil {
			return fmt.Errorf("device %q has a null entry", deviceID)
		}
		if dev.DeviceID != deviceID {
			return fmt.Errorf("device %q contains mismatched device_id %q", deviceID, dev.DeviceID)
		}
		ip := net.ParseIP(dev.IP).To4()
		if ip == nil || ip[0] != 10 || ip[1] != 66 || ip[2] != 66 || ip[3] < 2 || ip[3] > 250 {
			return fmt.Errorf("device %q has invalid tunnel IP %q", deviceID, dev.IP)
		}
		if previous, exists := usedIPs[dev.IP]; exists {
			return fmt.Errorf("devices %q and %q share tunnel IP %s", previous, deviceID, dev.IP)
		}
		if previous, exists := usedPublicKeys[dev.PubKey]; exists {
			return fmt.Errorf("devices %q and %q share a public key", previous, deviceID)
		}
		if err := validateKeyPair(dev.PrivKey, dev.PubKey); err != nil {
			return fmt.Errorf("device %q key pair: %w", deviceID, err)
		}
		usedIPs[dev.IP] = deviceID
		usedPublicKeys[dev.PubKey] = deviceID
	}
	return nil
}

func saveDBLazy() {
	dbRevision.Add(1)

	dbSaveMu.Lock()
	if dbSaveTimer == nil && !dbSaveInProgress {
		scheduleDBSaveLocked(dbSaveDelay)
	}
	dbSaveMu.Unlock()
}

func scheduleDBSaveLocked(delay time.Duration) {
	dbSaveTimer = time.AfterFunc(delay, runDelayedDBSave)
}

func databaseSaveRetryDelay(failures int) time.Duration {
	delay := dbSaveRetryMinDelay
	for attempt := 1; attempt < failures && delay < dbSaveRetryMaxDelay; attempt++ {
		if delay > dbSaveRetryMaxDelay/2 {
			return dbSaveRetryMaxDelay
		}
		delay *= 2
	}
	if delay > dbSaveRetryMaxDelay {
		return dbSaveRetryMaxDelay
	}
	return delay
}

func advanceSavedRevision(revision uint64) {
	for {
		current := dbSavedRevision.Load()
		if current >= revision || dbSavedRevision.CompareAndSwap(current, revision) {
			return
		}
	}
}

func runDelayedDBSave() {
	dbSaveMu.Lock()
	dbSaveTimer = nil
	dbSaveInProgress = true
	dbSaveMu.Unlock()

	targetRevision := dbRevision.Load()
	if targetRevision <= dbSavedRevision.Load() {
		dbSaveMu.Lock()
		dbSaveInProgress = false
		dbSaveFailures = 0
		dbSaveMu.Unlock()
		return
	}

	err := persistDatabase()
	dbSaveMu.Lock()
	dbSaveInProgress = false
	if err != nil {
		dbSaveFailures++
		retryDelay := databaseSaveRetryDelay(dbSaveFailures)
		if dbSaveTimer == nil {
			scheduleDBSaveLocked(retryDelay)
		}
		dbSaveMu.Unlock()
		log.Printf("[DB] delayed save failed, retry in %s: %v", retryDelay, err)
		return
	}

	advanceSavedRevision(targetRevision)
	dbSaveFailures = 0
	if dbRevision.Load() > dbSavedRevision.Load() && dbSaveTimer == nil {
		scheduleDBSaveLocked(dbSaveDelay)
	}
	dbSaveMu.Unlock()
}

func flushDB() error {
	dbSaveMu.Lock()
	timer := dbSaveTimer
	dbSaveTimer = nil
	dbSaveMu.Unlock()
	if timer != nil {
		timer.Stop()
	}

	for {
		targetRevision := dbRevision.Load()
		if err := persistDatabase(); err != nil {
			return err
		}
		advanceSavedRevision(targetRevision)

		dbSaveMu.Lock()
		if dbRevision.Load() == targetRevision {
			timer = dbSaveTimer
			dbSaveTimer = nil
			dbSaveFailures = 0
			dbSaveMu.Unlock()
			if timer != nil {
				timer.Stop()
			}
			return nil
		}
		dbSaveMu.Unlock()
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
	dir := filepath.Dir(dbFile)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create database directory: %w", err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return fmt.Errorf("secure database directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".passwords-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return fmt.Errorf("secure temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, dbFile); err != nil {
		return fmt.Errorf("replace database: %w", err)
	}
	dirHandle, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open database directory for sync: %w", err)
	}
	defer dirHandle.Close()
	if err := dirHandle.Sync(); err != nil {
		return fmt.Errorf("sync database directory: %w", err)
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

type telegramUpdate struct {
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
}

type telegramUpdatesResponse struct {
	OK          bool             `json:"ok"`
	Description string           `json:"description"`
	Result      []telegramUpdate `json:"result"`
	Parameters  struct {
		RetryAfter int `json:"retry_after"`
	} `json:"parameters"`
}

func telegramPollingBackoff(failures int) time.Duration {
	delay := telegramPollingMinBackoff
	for attempt := 1; attempt < failures && delay < telegramPollingMaxBackoff; attempt++ {
		if delay > telegramPollingMaxBackoff/2 {
			return telegramPollingMaxBackoff
		}
		delay *= 2
	}
	if delay > telegramPollingMaxBackoff {
		return telegramPollingMaxBackoff
	}
	return delay
}

func waitForTelegramRetry(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func getTelegramUpdates(ctx context.Context, client *http.Client, token string, offset int) ([]telegramUpdate, time.Duration, error) {
	url := fmt.Sprintf("%s/bot%s/getUpdates?timeout=60&offset=%d", strings.TrimRight(telegramAPIBaseURL, "/"), token, offset)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("create request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("request failed: %s", strings.ReplaceAll(err.Error(), token, "<redacted>"))
	}
	defer resp.Body.Close()

	const maxResponseSize = 2 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
	if err != nil {
		return nil, 0, fmt.Errorf("read response: %w", err)
	}
	if len(body) > maxResponseSize {
		return nil, 0, errors.New("response exceeds 2 MiB")
	}

	var result telegramUpdatesResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, 0, fmt.Errorf("decode response: %w", err)
	}
	retryAfter := time.Duration(result.Parameters.RetryAfter) * time.Second
	if retryAfter == 0 {
		if seconds, parseErr := strconv.Atoi(resp.Header.Get("Retry-After")); parseErr == nil && seconds > 0 {
			retryAfter = time.Duration(seconds) * time.Second
		}
	}
	description := strings.ReplaceAll(strings.TrimSpace(result.Description), token, "<redacted>")
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, retryAfter, fmt.Errorf("HTTP %d: %s", resp.StatusCode, description)
	}
	if !result.OK {
		return nil, retryAfter, fmt.Errorf("API rejected getUpdates: %s", description)
	}
	return result.Result, 0, nil
}

func botLoop(ctx context.Context, token string, adminIDstr string, wgDev *device.Device) {
	if token == "" || adminIDstr == "" {
		return
	}
	adminID, _ := strconv.ParseInt(adminIDstr, 10, 64)
	if adminID == 0 {
		return
	}

	payload := map[string]interface{}{
		"commands": []map[string]string{
			{"command": "start", "description": "Главное меню"},
			{"command": "new", "description": "Создать временный пароль"},
			{"command": "list", "description": "Управление доступами"},
		},
	}
	if err := postTelegram(token, "setMyCommands", payload); err != nil {
		log.Printf("[TG] setMyCommands: %v", err)
	}

	offset := 0
	pollFailures := 0

	var waitingForDays bool
	var waitingForPorts bool
	var waitingForHash bool
	var targetPassword string

	var tempDays int
	var tempPorts string

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		updates, retryAfter, err := getTelegramUpdates(ctx, telegramPollingHTTPClient, token, offset)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			pollFailures++
			delay := telegramPollingBackoff(pollFailures)
			if retryAfter > delay {
				delay = retryAfter
			}
			if delay > telegramPollingMaxBackoff {
				delay = telegramPollingMaxBackoff
			}
			log.Printf("[TG] getUpdates failed, retry in %s: %v", delay, err)
			if !waitForTelegramRetry(ctx, delay) {
				return
			}
			continue
		}
		pollFailures = 0

		for _, u := range updates {
			offset = u.UpdateID + 1

			if u.CallbackQuery != nil && u.CallbackQuery.Message.Chat.ID == adminID {
				data := u.CallbackQuery.Data
				if err := postTelegram(token, "answerCallbackQuery", map[string]interface{}{
					"callback_query_id": u.CallbackQuery.ID,
				}); err != nil {
					log.Printf("[TG] answerCallbackQuery: %v", err)
				}

				if strings.HasPrefix(data, "viewpass_") {

					pass := strings.TrimPrefix(data, "viewpass_")
					dbMutex.Lock()
					entry, exists := db.Passwords[pass]
					if !exists || entry == nil {
						dbMutex.Unlock()
						sendTelegram(token, adminID, "❌ Пароль не найден", nil)
						continue
					}
					entrySnapshot := *entry
					var deviceSnapshot *ClientDevice
					if dev := db.Devices[entry.DeviceID]; dev != nil {
						copy := *dev
						deviceSnapshot = &copy
					}
					dbMutex.Unlock()
					entry = &entrySnapshot
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
						if deviceSnapshot != nil {
							txt += fmt.Sprintf("• ID: `%s`\n• IP: `%s`\n", entry.DeviceID, deviceSnapshot.IP)
						} else {
							txt += fmt.Sprintf("• ID: `%s` (устройство удалено)\n", entry.DeviceID)
						}
						kb = append(kb, map[string]interface{}{
							"text":          "🗑 Отвязать устройство",
							"callback_data": "unbind_" + pass,
						})
					}
					isDeactivated := entry.IsDeactivated
					if isDeactivated {
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
					_, peerErr := deactivateGeneratedPassword(wgDev, pass)
					if peerErr != nil {
						log.Printf("[WG] Деактивация %s: %v", maskPassword(pass), peerErr)
						sendTelegram(token, adminID, fmt.Sprintf("⚠️ Пароль `%s` деактивирован, но WireGuard peer удалить не удалось", pass), nil)
					} else {
						sendTelegram(token, adminID, fmt.Sprintf("⏸ Пароль `%s` деактивирован", pass), nil)
					}

				} else if strings.HasPrefix(data, "react_") {
					pass := strings.TrimPrefix(data, "react_")
					reactivateGeneratedPassword(pass)
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
					_, peerErr := unbindGeneratedPassword(wgDev, pass)
					if peerErr != nil {
						log.Printf("[WG] Отвязка %s: %v", maskPassword(pass), peerErr)
						sendTelegram(token, adminID, fmt.Sprintf("❌ Не удалось удалить WireGuard peer для пароля `%s`", pass), nil)
					} else {
						sendTelegram(token, adminID, fmt.Sprintf("✅ Устройство отвязано от пароля `%s`", pass), nil)
					}

				} else if strings.HasPrefix(data, "delpass_") {
					pass := strings.TrimPrefix(data, "delpass_")
					_, peerErr := deleteGeneratedPassword(wgDev, pass)
					if peerErr != nil {
						log.Printf("[WG] Удаление пароля %s: %v", maskPassword(pass), peerErr)
						sendTelegram(token, adminID, fmt.Sprintf("❌ Не удалось удалить WireGuard peer для пароля `%s`; пароль сохранён", pass), nil)
					} else {
						sendTelegram(token, adminID, fmt.Sprintf("✅ Пароль `%s` и его устройство удалены", pass), nil)
					}

				} else if strings.HasPrefix(data, "deldev_") {
					callbackToken := strings.TrimPrefix(data, "deldev_")
					devID, exists, peerErr := deleteMainDevice(wgDev, callbackToken)
					if !exists {
						sendTelegram(token, adminID, "❌ Устройство главного пароля не найдено или список уже устарел", nil)
					} else if peerErr != nil {
						log.Printf("[WG] Удаление устройства %s: %v", devID, peerErr)
						sendTelegram(token, adminID, fmt.Sprintf("❌ Не удалось удалить WireGuard peer устройства `%s`", devID), nil)
					} else {
						sendTelegram(token, adminID, fmt.Sprintf("✅ Устройство `%s` удалено", devID), nil)
					}

				} else if strings.HasPrefix(data, "listpage_") {
					page, pageErr := strconv.Atoi(strings.TrimPrefix(data, "listpage_"))
					if pageErr == nil && page >= 0 {
						sendPasswordListPage(token, adminID, wgDev, page)
					}
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
				canonicalPorts, portErr := parsePortTriplet(cmd)
				if portErr != nil {
					sendTelegram(token, adminID, fmt.Sprintf("❌ Неверные порты: %v. Укажите три разных значения от 1 до 65535:", portErr), nil)
					continue
				}

				waitingForPorts = false
				tempPorts = canonicalPorts
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

				removed, cleanupErr := cleanupExpiredPasswords(wgDev)
				if cleanupErr != nil {
					log.Printf("[DB] Очистка истёкших паролей: %v", cleanupErr)
				}
				if removed > 0 {
					log.Printf("[DB] Удалено истёкших паролей: %d", removed)
				}
				dbMutex.Lock()
				if len(db.Passwords) >= maxGeneratedPasswords {
					dbMutex.Unlock()
					sendTelegram(token, adminID, fmt.Sprintf("❌ Лимит паролей: максимум %d активных. Удалите ненужный пароль через /list.", maxGeneratedPasswords), nil)
					continue
				}
				newPass := ""
				var generateErr error
				for i := 0; i < 10; i++ {
					candidate, err := generatePassword()
					if err != nil {
						generateErr = err
						break
					}
					if _, exists := db.Passwords[candidate]; !exists {
						newPass = candidate
						break
					}
				}
				if newPass == "" {
					dbMutex.Unlock()
					if generateErr != nil {
						log.Printf("[DB] Генерация пароля: %v", generateErr)
						sendTelegram(token, adminID, "❌ Системный генератор случайных чисел недоступен. Пароль не создан.", nil)
						continue
					}
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
				setPasswordAccessState(newPass, false, true, expiresAt)
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
				removed, cleanupErr := cleanupExpiredPasswords(wgDev)
				if cleanupErr != nil {
					log.Printf("[DB] Очистка истёкших паролей: %v", cleanupErr)
				}
				if removed > 0 {
					log.Printf("[DB] Удалено истёкших паролей: %d", removed)
				}
				dbMutex.Lock()
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

func removePeerFromWG(wgDev *device.Device, dev *ClientDevice) error {
	if wgDev == nil || dev == nil || dev.PubKey == "" {
		return errors.New("missing WireGuard device or peer key")
	}
	pubHex, err := b64ToHex(dev.PubKey)
	if err != nil {
		return fmt.Errorf("decode peer public key: %w", err)
	}
	if err := wgDev.IpcSet(fmt.Sprintf("public_key=%s\nremove=true\n", pubHex)); err != nil {
		return fmt.Errorf("remove peer %s: %w", dev.DeviceID, err)
	}
	return nil
}

func upsertPeerInWG(wgDev *device.Device, dev *ClientDevice) error {
	if wgDev == nil || dev == nil || dev.PubKey == "" || dev.IP == "" {
		return errors.New("missing WireGuard device, peer key, or peer IP")
	}
	pubHex, err := b64ToHex(dev.PubKey)
	if err != nil {
		return fmt.Errorf("decode peer public key: %w", err)
	}
	if err := wgDev.IpcSet(fmt.Sprintf("public_key=%s\nallowed_ip=%s/32\n", pubHex, dev.IP)); err != nil {
		return fmt.Errorf("upsert peer %s: %w", dev.DeviceID, err)
	}
	return nil
}

func deactivateGeneratedPassword(wgDev *device.Device, password string) (bool, error) {
	peerMutationMu.Lock()
	defer peerMutationMu.Unlock()

	dbMutex.Lock()
	entry, exists := db.Passwords[password]
	if !exists || entry == nil {
		dbMutex.Unlock()
		return false, nil
	}
	entry.IsDeactivated = true
	disablePasswordAccessState(password, false)
	var deviceSnapshot *ClientDevice
	if dev := db.Devices[entry.DeviceID]; dev != nil {
		copy := *dev
		deviceSnapshot = &copy
	}
	saveDBLazy()
	dbMutex.Unlock()

	if deviceSnapshot != nil {
		return true, removePeerFromWG(wgDev, deviceSnapshot)
	}
	return true, nil
}

func reactivateGeneratedPassword(password string) bool {
	peerMutationMu.Lock()
	defer peerMutationMu.Unlock()
	dbMutex.Lock()
	defer dbMutex.Unlock()
	entry, exists := db.Passwords[password]
	if !exists || entry == nil || isPasswordExpired(entry) {
		return false
	}
	entry.IsDeactivated = false
	setPasswordAccessState(password, false, true, entry.ExpiresAt)
	saveDBLazy()
	return true
}

func unbindGeneratedPassword(wgDev *device.Device, password string) (bool, error) {
	peerMutationMu.Lock()
	defer peerMutationMu.Unlock()

	dbMutex.RLock()
	entry, exists := db.Passwords[password]
	if !exists || entry == nil || entry.DeviceID == "" {
		dbMutex.RUnlock()
		return false, nil
	}
	deviceID := entry.DeviceID
	var deviceSnapshot *ClientDevice
	if dev := db.Devices[deviceID]; dev != nil {
		copy := *dev
		deviceSnapshot = &copy
	}
	dbMutex.RUnlock()

	if deviceSnapshot != nil {
		if err := removePeerFromWG(wgDev, deviceSnapshot); err != nil {
			return true, err
		}
	}

	dbMutex.Lock()
	if current := db.Passwords[password]; current != nil && current.DeviceID == deviceID {
		delete(db.Devices, deviceID)
		current.DeviceID = ""
		saveDBLazy()
	}
	dbMutex.Unlock()
	return true, nil
}

func deleteGeneratedPassword(wgDev *device.Device, password string) (bool, error) {
	peerMutationMu.Lock()
	defer peerMutationMu.Unlock()

	dbMutex.RLock()
	entry, exists := db.Passwords[password]
	if !exists || entry == nil {
		dbMutex.RUnlock()
		return false, nil
	}
	entrySnapshot := *entry
	var deviceSnapshot *ClientDevice
	if dev := db.Devices[entry.DeviceID]; dev != nil {
		copy := *dev
		deviceSnapshot = &copy
	}
	dbMutex.RUnlock()

	disablePasswordAccessState(password, false)
	if deviceSnapshot != nil {
		if err := removePeerFromWG(wgDev, deviceSnapshot); err != nil {
			setPasswordAccessState(password, false, !entrySnapshot.IsDeactivated && !isPasswordExpired(&entrySnapshot), entrySnapshot.ExpiresAt)
			return true, err
		}
	}

	dbMutex.Lock()
	if current := db.Passwords[password]; current != nil {
		delete(db.Devices, current.DeviceID)
		delete(db.Passwords, password)
		saveDBLazy()
	}
	dbMutex.Unlock()
	serverWrapKeys.RemovePassword(password)
	return true, nil
}

func deleteMainDevice(wgDev *device.Device, callbackToken string) (string, bool, error) {
	peerMutationMu.Lock()
	defer peerMutationMu.Unlock()

	dbMutex.RLock()
	deviceID, dev, exists := findMainDeviceByCallbackToken(db, callbackToken)
	if !exists {
		dbMutex.RUnlock()
		return "", false, nil
	}
	deviceSnapshot := *dev
	dbMutex.RUnlock()

	if err := removePeerFromWG(wgDev, &deviceSnapshot); err != nil {
		return deviceID, true, err
	}
	dbMutex.Lock()
	if current := db.Devices[deviceID]; current != nil && current.PubKey == deviceSnapshot.PubKey {
		delete(db.Devices, deviceID)
		saveDBLazy()
	}
	dbMutex.Unlock()
	return deviceID, true, nil
}

func cleanupExpiredPasswords(wgDev *device.Device) (int, error) {
	peerMutationMu.Lock()
	defer peerMutationMu.Unlock()

	type expiredPassword struct {
		password string
		entry    *PasswordEntry
		device   *ClientDevice
	}
	dbMutex.RLock()
	expired := make([]expiredPassword, 0)
	for password, entry := range db.Passwords {
		if !isPasswordExpired(entry) {
			continue
		}
		item := expiredPassword{password: password, entry: entry}
		if entry != nil {
			if dev := db.Devices[entry.DeviceID]; dev != nil {
				copy := *dev
				item.device = &copy
			}
		}
		expired = append(expired, item)
	}
	dbMutex.RUnlock()

	removed := 0
	var cleanupErrors []error
	for _, item := range expired {
		disablePasswordAccessState(item.password, false)
		serverWrapKeys.RemovePassword(item.password)
		if item.device != nil {
			if err := removePeerFromWG(wgDev, item.device); err != nil {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("expire password %s: %w", maskPassword(item.password), err))
				continue
			}
		}

		dbMutex.Lock()
		if current := db.Passwords[item.password]; current == item.entry {
			if current != nil {
				delete(db.Devices, current.DeviceID)
			}
			delete(db.Passwords, item.password)
			removed++
		}
		dbMutex.Unlock()
	}
	if removed > 0 {
		saveDBLazy()
	}
	return removed, errors.Join(cleanupErrors...)
}

func expiredPasswordJanitor(ctx context.Context, wgDev *device.Device) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			removed, err := cleanupExpiredPasswords(wgDev)
			if err != nil {
				log.Printf("[DB] Очистка истёкших паролей: %v", err)
			}
			if removed > 0 {
				log.Printf("[DB] Удалено истёкших паролей: %d", removed)
			}
		}
	}
}

func syncPersistedPeersToWG(wgDev *device.Device) error {
	peerMutationMu.Lock()
	defer peerMutationMu.Unlock()

	dbMutex.RLock()
	devices := make(map[string]ClientDevice, len(db.Devices))
	for deviceID, dev := range db.Devices {
		if dev != nil {
			devices[deviceID] = *dev
		}
	}
	dbMutex.RUnlock()

	count := 0
	for deviceID, dev := range devices {
		if err := upsertPeerInWG(wgDev, &dev); err != nil {
			return fmt.Errorf("device %s: %w", deviceID, err)
		}
		count++
	}
	if count > 0 {
		log.Printf("[WG] Восстановлено сохранённых устройств: %d", count)
	}
	return nil
}

const telegramListPageSize = 15

func sendPasswordList(token string, adminID int64, wgDev *device.Device) {
	sendPasswordListPage(token, adminID, wgDev, 0)
}

func sendPasswordListPage(token string, adminID int64, wgDev *device.Device, page int) {
	removed, cleanupErr := cleanupExpiredPasswords(wgDev)
	if cleanupErr != nil {
		log.Printf("[DB] Очистка истёкших паролей: %v", cleanupErr)
	}
	if removed > 0 {
		log.Printf("[DB] Удалено истёкших паролей: %d", removed)
	}
	dbMutex.RLock()

	txt := "🔐 *Пароли:*\n\n"
	txt += fmt.Sprintf("🔒 Главный: `%s` (владелец)\n", db.MainPassword)

	var keyboard [][]map[string]interface{}
	keyboard = append(keyboard, []map[string]interface{}{{
		"text":          "🔗 Ссылка на главный пароль",
		"callback_data": "mainlink",
	}})
	mainDevices := mainDeviceIDs(db)
	totalPages := (len(mainDevices) + telegramListPageSize - 1) / telegramListPageSize
	if totalPages == 0 {
		totalPages = 1
	}
	if page >= totalPages {
		page = totalPages - 1
	}
	if page < 0 {
		page = 0
	}
	start := page * telegramListPageSize
	end := start + telegramListPageSize
	if end > len(mainDevices) {
		end = len(mainDevices)
	}
	if len(mainDevices) == 0 {
		txt += "📱 Устройства: _нет_\n\n"
	} else {
		txt += fmt.Sprintf("📱 Устройства главного пароля: %d (страница %d/%d)\n", len(mainDevices), page+1, totalPages)
		for _, deviceID := range mainDevices[start:end] {
			dev := db.Devices[deviceID]
			txt += fmt.Sprintf("• `%s` — `%s`\n", deviceID, dev.IP)
			label := deviceID
			if len(label) > 20 {
				label = label[:20] + "…"
			}
			keyboard = append(keyboard, []map[string]interface{}{{
				"text":          "🗑 " + label,
				"callback_data": "deldev_" + deviceCallbackToken(deviceID),
			}})
		}
		txt += "\n"
	}

	if len(db.Passwords) == 0 {
		txt += "_Нет сгенерированных паролей._\n"
	} else {
		txt += fmt.Sprintf("_Активно: %d/%d_\n\n", len(db.Passwords), maxGeneratedPasswords)
		passwords := make([]string, 0, len(db.Passwords))
		for password := range db.Passwords {
			passwords = append(passwords, password)
		}
		sort.Strings(passwords)
		for _, p := range passwords {
			entry := db.Passwords[p]
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
			keyboard = append(keyboard, []map[string]interface{}{{
				"text":          "🔍 " + p,
				"callback_data": "viewpass_" + p,
			}})
		}
	}

	txt += "\n🟢 = свободен | 🔗 = привязан"
	if totalPages > 1 {
		var navigation []map[string]interface{}
		if page > 0 {
			navigation = append(navigation, map[string]interface{}{
				"text":          "⬅️ Назад",
				"callback_data": fmt.Sprintf("listpage_%d", page-1),
			})
		}
		if page+1 < totalPages {
			navigation = append(navigation, map[string]interface{}{
				"text":          "Вперёд ➡️",
				"callback_data": fmt.Sprintf("listpage_%d", page+1),
			})
		}
		if len(navigation) > 0 {
			keyboard = append(keyboard, navigation)
		}
	}
	dbMutex.RUnlock()
	sendTelegram(token, adminID, txt, map[string]interface{}{"inline_keyboard": keyboard})
}

func maskPassword(pass string) string {
	if len(pass) <= 3 {
		return pass
	}
	return pass[:3] + "****"
}

var (
	telegramHTTPClient        = &http.Client{Timeout: 15 * time.Second}
	telegramPollingHTTPClient = &http.Client{Timeout: 65 * time.Second}
	telegramAPIBaseURL        = "https://api.telegram.org"
	telegramPollingMinBackoff = 2 * time.Second
	telegramPollingMaxBackoff = time.Minute
)

func postTelegram(token, method string, payload interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}
	url := fmt.Sprintf("%s/bot%s/%s", strings.TrimRight(telegramAPIBaseURL, "/"), token, method)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := telegramHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %s", strings.ReplaceAll(err.Error(), token, "<redacted>"))
	}
	defer resp.Body.Close()
	responseBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if readErr != nil {
		return fmt.Errorf("read response: %w", readErr)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		detail := strings.ReplaceAll(strings.TrimSpace(string(responseBody)), token, "<redacted>")
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, detail)
	}
	var telegramResult struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(responseBody, &telegramResult); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	if !telegramResult.OK {
		detail := strings.ReplaceAll(telegramResult.Description, token, "<redacted>")
		return fmt.Errorf("API rejected request: %s", detail)
	}
	return nil
}

func sendTelegram(token string, chatID int64, text string, replyMarkup interface{}) {
	payload := map[string]interface{}{
		"chat_id":    chatID,
		"text":       text,
		"parse_mode": "Markdown",
	}
	if replyMarkup != nil {
		payload["reply_markup"] = replyMarkup
	}
	if err := postTelegram(token, "sendMessage", payload); err != nil {
		log.Printf("[TG] sendMessage: %v", err)
	}
}
