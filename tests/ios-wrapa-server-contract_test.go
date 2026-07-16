package proxy

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestServerCompatibilityGoldenVector is copied into the iOS repository by
// Server CI, so the fixture exercises its real unexported WRAP-A code.
func TestServerCompatibilityGoldenVector(t *testing.T) {
	const (
		password = "WDTT-Compat-Vector-01"
		keyHex   = "1b49bd81dcc3a338bdce318446127650e5439b4ac5739efe80810d3e80073d84"
		wireHex  = "a0ef5566778899aa112233442f5aa4bcda46d067dfc595533dc454ef0998772f70c3f463b4b25949016d20ae545702d9b05d2fe76b0102030405"
		plain    = "WDTT compatibility vector"
	)

	key, err := deriveWrapAKey(password)
	if err != nil {
		t.Fatalf("deriveWrapAKey: %v", err)
	}
	if got := hex.EncodeToString(key); got != keyHex {
		t.Fatalf("derived key = %s, want %s", got, keyHex)
	}
	wire, err := hex.DecodeString(wireHex)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	connection, err := newWrapAPacketConn(nil, nil, key)
	if err != nil {
		t.Fatalf("newWrapAPacketConn: %v", err)
	}
	out := make([]byte, 256)
	n, err := connection.wrapAUnwrap(wire, out)
	if err != nil {
		t.Fatalf("unwrap server fixture: %v", err)
	}
	if !bytes.Equal(out[:n], []byte(plain)) {
		t.Fatalf("plaintext = %q, want %q", out[:n], plain)
	}
	var nonce [12]byte
	wrapABuildNonce(&nonce, 0x11223344, 0x5566, 0x778899aa)
	if got := hex.EncodeToString(nonce[:]); got != "1122334455660000778899aa" {
		t.Fatalf("nonce = %s", got)
	}
}
