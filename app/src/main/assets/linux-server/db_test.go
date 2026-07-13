package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInitDBRejectsCorruptDatabaseWithoutOverwritingIt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "passwords.json")
	original := []byte(`{"passwords":`)
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if err := initDB(dir, "strong-test-password", "", ""); err == nil {
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
	if err := initDB(dir, "strong-test-password", "", ""); err != nil {
		t.Fatalf("initDB: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "passwords.json")); err != nil {
		t.Fatalf("database was not created: %v", err)
	}
}
