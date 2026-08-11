package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type recordingReadDeadlineSetter struct {
	deadlines []time.Time
}

func (c *recordingReadDeadlineSetter) SetReadDeadline(deadline time.Time) error {
	c.deadlines = append(c.deadlines, deadline)
	return nil
}

func TestRelayReadDeadlineRefreshIsThrottled(t *testing.T) {
	conn := &recordingReadDeadlineSetter{}
	var refresher relayReadDeadlineRefresher
	start := time.Unix(1_700_000_000, 0)
	idleTimeout := 3 * time.Minute

	for _, elapsed := range []time.Duration{0, time.Second, relayDeadlineRefreshInterval - time.Nanosecond} {
		if err := refresher.refresh(conn, start.Add(elapsed), idleTimeout); err != nil {
			t.Fatalf("refresh at %s: %v", elapsed, err)
		}
	}
	if len(conn.deadlines) != 1 {
		t.Fatalf("deadline updates = %d, want 1", len(conn.deadlines))
	}
	if want := start.Add(idleTimeout + relayDeadlineRefreshInterval); !conn.deadlines[0].Equal(want) {
		t.Fatalf("first deadline = %s, want %s", conn.deadlines[0], want)
	}

	next := start.Add(relayDeadlineRefreshInterval)
	if err := refresher.refresh(conn, next, idleTimeout); err != nil {
		t.Fatalf("refresh at interval: %v", err)
	}
	if len(conn.deadlines) != 2 {
		t.Fatalf("deadline updates = %d, want 2", len(conn.deadlines))
	}
	if want := next.Add(idleTimeout + relayDeadlineRefreshInterval); !conn.deadlines[1].Equal(want) {
		t.Fatalf("second deadline = %s, want %s", conn.deadlines[1], want)
	}
}

func TestAddTrafficIsImmediatelyVisible(t *testing.T) {
	var total int64
	var passwordTotal int64
	addTraffic(&total, &passwordTotal, 512, true)
	if got := atomic.LoadInt64(&total); got != 512 {
		t.Fatalf("total traffic = %d, want 512", got)
	}
	if got := atomic.LoadInt64(&passwordTotal); got != 512 {
		t.Fatalf("password traffic = %d, want 512", got)
	}
	addTraffic(&total, &passwordTotal, 256, false)
	if got := atomic.LoadInt64(&total); got != 768 {
		t.Fatalf("total traffic = %d, want 768", got)
	}
	if got := atomic.LoadInt64(&passwordTotal); got != 512 {
		t.Fatalf("untracked password traffic = %d, want 512", got)
	}
}

func TestDefaultInterfaceFromRoutes(t *testing.T) {
	routes := "default via 192.0.2.1 dev ens3 proto dhcp src 192.0.2.10\n192.0.2.0/24 dev ens3"
	if got := defaultInterfaceFromRoutes(routes); got != "ens3" {
		t.Fatalf("defaultInterfaceFromRoutes() = %q, want ens3", got)
	}
	if got := defaultInterfaceFromRoutes("10.0.0.0/8 dev eth0"); got != "" {
		t.Fatalf("route without default returned %q", got)
	}
}

func TestLoadOrGenerateKeysRejectsCorruptExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wg-keys.dat")
	original := []byte("not-a-valid-key-file\n")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if _, err := loadOrGenerateKeys(dir); err == nil {
		t.Fatal("loadOrGenerateKeys accepted a corrupt key file")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(after) != string(original) {
		t.Fatalf("corrupt key file was overwritten: %q", after)
	}
}

func TestLoadOrGenerateKeysPersistsValidPairs(t *testing.T) {
	dir := t.TempDir()
	generated, err := loadOrGenerateKeys(dir)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	loaded, err := loadOrGenerateKeys(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if *loaded != *generated {
		t.Fatal("reloaded keys differ from generated keys")
	}
	info, err := os.Stat(filepath.Join(dir, "wg-keys.dat"))
	if err != nil {
		t.Fatalf("stat persisted keys: %v", err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("key permissions = %04o, want 0600", got)
	}
}

func TestLoadOrGenerateKeysMigratesLegacyFourLineFile(t *testing.T) {
	dir := t.TempDir()
	serverPrivate, serverPublic, err := generateKeyPair()
	if err != nil {
		t.Fatalf("generate server pair: %v", err)
	}
	clientPrivate, clientPublic, err := generateKeyPair()
	if err != nil {
		t.Fatalf("generate legacy client pair: %v", err)
	}
	path := filepath.Join(dir, "wg-keys.dat")
	legacy := strings.Join([]string{serverPrivate, serverPublic, clientPrivate, clientPublic, ""}, "\n")
	if err := os.WriteFile(path, []byte(legacy), 0600); err != nil {
		t.Fatalf("write legacy keys: %v", err)
	}

	keys, err := loadOrGenerateKeys(dir)
	if err != nil {
		t.Fatalf("loadOrGenerateKeys: %v", err)
	}
	if keys.serverPrivate != serverPrivate || keys.serverPublic != serverPublic {
		t.Fatal("server identity changed during migration")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migrated file: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 || lines[0] != serverPrivate || lines[1] != serverPublic {
		t.Fatalf("migrated key file has %d lines, want the original server pair", len(lines))
	}
}
