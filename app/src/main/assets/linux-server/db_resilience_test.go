package main

import (
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func resetDelayedSaveStateForTest() {
	dbSaveMu.Lock()
	if dbSaveTimer != nil {
		dbSaveTimer.Stop()
	}
	dbSaveTimer = nil
	dbSaveInProgress = false
	dbSaveFailures = 0
	dbRevision.Store(0)
	dbSavedRevision.Store(0)
	dbSaveMu.Unlock()
}

func TestDelayedSaveRetriesAfterTransientFailure(t *testing.T) {
	oldPersist := persistDatabase
	oldSaveDelay := dbSaveDelay
	oldRetryMin := dbSaveRetryMinDelay
	oldRetryMax := dbSaveRetryMaxDelay
	resetDelayedSaveStateForTest()
	dbSaveDelay = 5 * time.Millisecond
	dbSaveRetryMinDelay = 5 * time.Millisecond
	dbSaveRetryMaxDelay = 20 * time.Millisecond

	var attempts atomic.Int32
	saved := make(chan struct{}, 1)
	persistDatabase = func() error {
		if attempts.Add(1) == 1 {
			return errors.New("injected persistence failure")
		}
		select {
		case saved <- struct{}{}:
		default:
		}
		return nil
	}
	t.Cleanup(func() {
		resetDelayedSaveStateForTest()
		persistDatabase = oldPersist
		dbSaveDelay = oldSaveDelay
		dbSaveRetryMinDelay = oldRetryMin
		dbSaveRetryMaxDelay = oldRetryMax
	})

	saveDBLazy()
	select {
	case <-saved:
	case <-time.After(2 * time.Second):
		t.Fatal("deferred save did not retry after the injected failure")
	}

	deadline := time.Now().Add(time.Second)
	for dbSavedRevision.Load() < dbRevision.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := attempts.Load(); got != 2 {
		t.Fatalf("persistence attempts = %d, want 2", got)
	}
	if dbSavedRevision.Load() != dbRevision.Load() {
		t.Fatalf("saved revision = %d, current revision = %d", dbSavedRevision.Load(), dbRevision.Load())
	}
}

func TestCriticalSaveReportsPersistenceFailure(t *testing.T) {
	oldPersist := persistDatabase
	oldRetryMin := dbSaveRetryMinDelay
	oldRetryMax := dbSaveRetryMaxDelay
	resetDelayedSaveStateForTest()
	dbSaveRetryMinDelay = time.Hour
	dbSaveRetryMaxDelay = time.Hour
	persistDatabase = func() error {
		return errors.New("injected persistence failure")
	}
	t.Cleanup(func() {
		resetDelayedSaveStateForTest()
		persistDatabase = oldPersist
		dbSaveRetryMinDelay = oldRetryMin
		dbSaveRetryMaxDelay = oldRetryMax
	})

	if err := saveDBCritical(); err == nil {
		t.Fatal("critical save reported success after a persistence failure")
	}
	if dbSavedRevision.Load() == dbRevision.Load() {
		t.Fatal("failed critical save was marked as durable")
	}
}

func TestDeletePasswordRevokesWrapKeyAfterPersistenceFailure(t *testing.T) {
	resetDelayedSaveStateForTest()
	oldPersist := persistDatabase
	oldDB := db
	oldWrapKeys := serverWrapKeys
	defer func() {
		resetDelayedSaveStateForTest()
		persistDatabase = oldPersist
		db = oldDB
		serverWrapKeys = oldWrapKeys
	}()

	const (
		mainPassword = "Main-Test_7kM9xQ2"
		password     = "temporary-delete"
	)
	db = &Database{
		MainPassword: mainPassword,
		Passwords: map[string]*PasswordEntry{
			password: {ExpiresAt: time.Now().Add(time.Hour).Unix()},
		},
		Devices: make(map[string]*ClientDevice),
	}
	serverWrapKeys = newWrapKeyStore()
	if err := serverWrapKeys.SetPasswords(mainPassword, []string{password}); err != nil {
		t.Fatalf("SetPasswords: %v", err)
	}
	existingState := setPasswordAccessState(password, false, true, db.Passwords[password].ExpiresAt)
	persistDatabase = func() error { return errors.New("injected persistence failure") }

	exists, err := deleteGeneratedPassword(nil, password)
	if !exists || err == nil {
		t.Fatalf("deleteGeneratedPassword = (%v, %v), want an existing password and persistence error", exists, err)
	}
	if serverWrapKeys.Count() != 1 {
		t.Fatalf("WRAP key count = %d, want only the main key", serverWrapKeys.Count())
	}
	if existingState.IsActive() {
		t.Fatal("an existing connection retained active access after password deletion")
	}
	if state := getPasswordAccessState(password, false); state != nil {
		t.Fatal("deleted password remained in the access-state map")
	}
	if _, exists := db.Passwords[password]; exists {
		t.Fatal("deleted password remained in the in-memory database")
	}
}

func TestRemovePasswordAccessStateInvalidatesExistingReaders(t *testing.T) {
	const password = "temporary-access-state"
	state := setPasswordAccessState(password, false, true, time.Now().Add(time.Hour).Unix())
	removePasswordAccessState(password, false)
	defer removePasswordAccessState(password, false)

	if state.IsActive() {
		t.Fatal("existing access-state reader remained active")
	}
	if current := getPasswordAccessState(password, false); current != nil {
		t.Fatal("removed access state remained discoverable")
	}
}

func validPersistentDatabaseForTest(t *testing.T) *Database {
	t.Helper()
	privateKey, publicKey, err := generateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	return &Database{
		Passwords: map[string]*PasswordEntry{
			"Generated-Test_7kM9": {DeviceID: "device-0001", Ports: "56000,56001,9000"},
		},
		Devices: map[string]*ClientDevice{
			"device-0001": {
				DeviceID: "device-0001",
				IP:       "10.66.66.2",
				PrivKey:  privateKey,
				PubKey:   publicKey,
			},
		},
	}
}

func TestValidatePersistentDatabaseRejectsSemanticCorruption(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Database)
	}{
		{
			name: "unsafe device ID",
			mutate: func(database *Database) {
				device := database.Devices["device-0001"]
				delete(database.Devices, "device-0001")
				device.DeviceID = "device\nunsafe"
				database.Devices[device.DeviceID] = device
				database.Passwords["Generated-Test_7kM9"].DeviceID = device.DeviceID
			},
		},
		{
			name: "mismatched map key",
			mutate: func(database *Database) {
				database.Devices["device-0001"].DeviceID = "device-0002"
			},
		},
		{
			name: "out of pool address",
			mutate: func(database *Database) {
				database.Devices["device-0001"].IP = "10.66.67.2"
			},
		},
		{
			name: "missing password binding",
			mutate: func(database *Database) {
				database.Passwords["Generated-Test_7kM9"].DeviceID = "missing-device"
			},
		},
		{
			name: "invalid key pair",
			mutate: func(database *Database) {
				database.Devices["device-0001"].PubKey = database.Devices["device-0001"].PrivKey
			},
		},
		{
			name: "duplicated address",
			mutate: func(database *Database) {
				privateKey, publicKey, err := generateKeyPair()
				if err != nil {
					t.Fatalf("generate second key pair: %v", err)
				}
				database.Devices["device-0002"] = &ClientDevice{
					DeviceID: "device-0002",
					IP:       "10.66.66.2",
					PrivKey:  privateKey,
					PubKey:   publicKey,
				}
			},
		},
		{
			name: "main password collision",
			mutate: func(database *Database) {
				database.MainPassword = "Generated-Test_7kM9"
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			database := validPersistentDatabaseForTest(t)
			test.mutate(database)
			if err := validatePersistentDatabase(database); err == nil {
				t.Fatal("validatePersistentDatabase accepted corrupted state")
			}
		})
	}
}

func TestParsePortTripletRequiresThreeDistinctValidPorts(t *testing.T) {
	if got, err := parsePortTriplet("56000, 56001, 9000"); err != nil || got != "56000,56001,9000" {
		t.Fatalf("valid triplet = %q, %v", got, err)
	}
	for _, invalid := range []string{
		"56000,56001",
		"56000,56000,9000",
		"0,56001,9000",
		"65536,56001,9000",
		"udp,56001,9000",
	} {
		if _, err := parsePortTriplet(invalid); err == nil {
			t.Fatalf("parsePortTriplet(%q) succeeded", invalid)
		}
	}
}

func TestNormalizeVKHashInputOnlyProducesPersistableValues(t *testing.T) {
	valid := map[string]string{
		"hash-one":                    "hash-one",
		" hash-one, hash_two.value ": "hash-one,hash_two.value",
	}
	for input, want := range valid {
		got, err := normalizeVKHashInput(input)
		if err != nil {
			t.Fatalf("normalizeVKHashInput(%q): %v", input, err)
		}
		if got != want {
			t.Fatalf("normalizeVKHashInput(%q) = %q, want %q", input, got, want)
		}
		if err := validateStoredVKHash(got); err != nil {
			t.Fatalf("normalized hash %q cannot be loaded from the database: %v", got, err)
		}
	}

	invalid := []string{
		"",
		"   ",
		"hash-one,,hash-two",
		",hash-one",
		"hash-one,",
		"hash\nwith-newline",
		"https://vk.example/hash",
		strings.Repeat("a", 2049),
	}
	for _, input := range invalid {
		if got, err := normalizeVKHashInput(input); err == nil {
			t.Fatalf("normalizeVKHashInput(%q) = %q, want an error", input, got)
		}
	}
}
