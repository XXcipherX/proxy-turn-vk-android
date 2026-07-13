package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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
	if _, err := os.Stat(filepath.Join(dir, "passwords.json")); err != nil {
		t.Fatalf("database was not created: %v", err)
	}
}
