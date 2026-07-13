package main

import (
	"os"
	"path/filepath"
	"testing"
)

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
}
