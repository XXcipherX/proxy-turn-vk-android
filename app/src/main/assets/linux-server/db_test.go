package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type failingPasswordReader struct{}

func (failingPasswordReader) Read([]byte) (int, error) {
	return 0, errors.New("random source failed")
}

func TestValidateMainPassword(t *testing.T) {
	valid := []string{
		"Strong-Test_7kM9xQ2",
		"f4c1a9e72d8b3605f1a4c9e72d8b",
		"A9d4Kp7_zQ2mN8xR",
	}
	for _, password := range valid {
		if err := validateMainPassword(password); err != nil {
			t.Errorf("validateMainPassword(%q): %v", password, err)
		}
	}

	invalid := []string{
		"short-pass",
		"password-password",
		"aaaaaaaaaaaaaaaa",
		"abcdefghijklmnop",
		"StrongPassword:123",
	}
	for _, password := range invalid {
		if err := validateMainPassword(password); err == nil {
			t.Errorf("validateMainPassword(%q) accepted weak password", password)
		}
	}
}

func TestGeneratePasswordFailsClosed(t *testing.T) {
	if _, err := generatePasswordFrom(failingPasswordReader{}); err == nil {
		t.Fatal("generatePasswordFrom accepted a failed random source")
	}

	password, err := generatePasswordFrom(strings.NewReader(strings.Repeat("\x01", 32)))
	if err != nil {
		t.Fatalf("generatePasswordFrom: %v", err)
	}
	if len(password) != generatedPasswordLen {
		t.Fatalf("generated password length = %d, want %d", len(password), generatedPasswordLen)
	}
	if strings.Trim(password, passChars) != "" {
		t.Fatalf("generated password contains unsupported characters: %q", password)
	}
}

func TestMainDeviceCallbacksExcludeGeneratedPasswordDevices(t *testing.T) {
	mainID := "main-device-0001"
	generatedID := "generated-device-0001"
	database := &Database{
		Passwords: map[string]*PasswordEntry{
			"generated-secret": {DeviceID: generatedID},
		},
		Devices: map[string]*ClientDevice{
			mainID:      {DeviceID: mainID, IP: "10.66.66.2"},
			generatedID: {DeviceID: generatedID, IP: "10.66.66.3"},
		},
	}

	ids := mainDeviceIDs(database)
	if len(ids) != 1 || ids[0] != mainID {
		t.Fatalf("mainDeviceIDs = %v, want [%s]", ids, mainID)
	}
	token := deviceCallbackToken(mainID)
	if len(token) != 16 || strings.Contains(token, mainID) {
		t.Fatalf("unsafe callback token %q", token)
	}
	gotID, gotDevice, ok := findMainDeviceByCallbackToken(database, token)
	if !ok || gotID != mainID || gotDevice != database.Devices[mainID] {
		t.Fatalf("findMainDeviceByCallbackToken = (%q, %v, %v)", gotID, gotDevice, ok)
	}
	if _, _, ok := findMainDeviceByCallbackToken(database, deviceCallbackToken(generatedID)); ok {
		t.Fatal("generated-password device was exposed as a main device")
	}
}

func TestInitDBRejectsCorruptDatabaseWithoutOverwritingIt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "passwords.json")
	original := []byte(`{"passwords":`)
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if err := initDB(dir, "Strong-Test_7kM9xQ2", "", ""); err == nil {
		t.Fatal("initDB accepted corrupt JSON")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(after) != string(original) {
		t.Fatalf("corrupt database was overwritten: %q", after)
	}
}

func TestInitDBCreatesMissingDatabase(t *testing.T) {
	dir := t.TempDir()
	if err := initDB(dir, "Strong-Test_7kM9xQ2", "", ""); err != nil {
		t.Fatalf("initDB: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, "passwords.json"))
	if err != nil {
		t.Fatalf("database was not created: %v", err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("database permissions = %04o, want 0600", got)
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat database directory: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != 0700 {
		t.Fatalf("database directory permissions = %04o, want 0700", got)
	}
}

func TestConcurrentDatabasePersistence(t *testing.T) {
	dir := t.TempDir()
	if err := initDB(dir, "Strong-Test_7kM9xQ2", "", ""); err != nil {
		t.Fatalf("initDB: %v", err)
	}

	const writers = 8
	const devicesPerWriter = 16
	var wg sync.WaitGroup
	for writer := 0; writer < writers; writer++ {
		writer := writer
		wg.Add(1)
		go func() {
			defer wg.Done()
			for device := 0; device < devicesPerWriter; device++ {
				deviceID := fmt.Sprintf("ci-device-%02d-%02d", writer, device)
				dbMutex.Lock()
				db.Devices[deviceID] = &ClientDevice{DeviceID: deviceID, IP: "10.66.66.2"}
				dbMutex.Unlock()
				saveDBLazy()
			}
		}()
	}
	wg.Wait()
	if err := flushDB(); err != nil {
		t.Fatalf("flushDB: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "passwords.json"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var persisted Database
	if err := json.Unmarshal(data, &persisted); err != nil {
		t.Fatalf("persisted database is invalid JSON: %v", err)
	}
	if got, want := len(persisted.Devices), writers*devicesPerWriter; got != want {
		t.Fatalf("persisted devices = %d, want %d", got, want)
	}
}
