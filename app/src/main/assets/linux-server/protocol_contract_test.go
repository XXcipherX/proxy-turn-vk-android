package main

import (
	"bytes"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
)

const (
	compatPassword = "WDTT-Compat-Vector-01"
	compatKeyHex   = "1b49bd81dcc3a338bdce318446127650e5439b4ac5739efe80810d3e80073d84"
	compatWireHex  = "a0ef5566778899aa112233442f5aa4bcda46d067dfc595533dc454ef0998772f70c3f463b4b25949016d20ae545702d9b05d2fe76b0102030405"
	compatPlain    = "WDTT compatibility vector"
)

// TestWireProtocolGoldenVector protects the wire contract shared by the
// Android client, the iOS WRAP-A client and this server. The fixture was
// generated independently from the Go implementation.
func TestWireProtocolGoldenVector(t *testing.T) {
	key, err := deriveWrapKey(compatPassword)
	if err != nil {
		t.Fatalf("deriveWrapKey: %v", err)
	}
	if got := hex.EncodeToString(key); got != compatKeyHex {
		t.Fatalf("derived key = %s, want %s", got, compatKeyHex)
	}

	wire, err := hex.DecodeString(compatWireHex)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if !obfsIsRTPPacket(wire) {
		t.Fatal("compatibility fixture was not recognized as RTP")
	}
	out := make([]byte, 256)
	n, err := obfsUnwrapPacket(key, wire, out)
	if err != nil {
		t.Fatalf("unwrap compatibility fixture: %v", err)
	}
	if !bytes.Equal(out[:n], []byte(compatPlain)) {
		t.Fatalf("plaintext = %q, want %q", out[:n], compatPlain)
	}

	wantNonce := "1122334455660000778899aa"
	if got := hex.EncodeToString(obfsBuildNonce(0x11223344, 0x5566, 0x778899aa)); got != wantNonce {
		t.Fatalf("nonce = %s, want %s", got, wantNonce)
	}
}

func TestParseGetConfRequest(t *testing.T) {
	tests := []struct {
		name       string
		packet     string
		recognized bool
		want       getConfRequest
		wantErr    bool
	}{
		{
			name:       "valid Android and iOS shape",
			packet:     "GETCONF:9000|550E8400-E29B-41D4-A716-446655440000|Strong-Test_7kM9xQ2",
			recognized: true,
			want: getConfRequest{
				ClientPort: "9000",
				DeviceID:   "550E8400-E29B-41D4-A716-446655440000",
				Password:   "Strong-Test_7kM9xQ2",
			},
		},
		{name: "not GETCONF", packet: "READY"},
		{name: "missing password", packet: "GETCONF:9000|device", recognized: true, wantErr: true},
		{name: "extra field", packet: "GETCONF:9000|device|secret|extra", recognized: true, wantErr: true},
		{name: "zero port", packet: "GETCONF:0|device|secret", recognized: true, wantErr: true},
		{name: "large port", packet: "GETCONF:65536|device|secret", recognized: true, wantErr: true},
		{name: "empty device", packet: "GETCONF:9000||secret", recognized: true, wantErr: true},
		{name: "device with newline", packet: "GETCONF:9000|device%0Aunsafe\n|secret", recognized: true, wantErr: true},
		{name: "device with delimiter", packet: "GETCONF:9000|device/unsafe|secret", recognized: true, wantErr: true},
		{name: "oversized device", packet: "GETCONF:9000|" + strings.Repeat("a", 129) + "|secret", recognized: true, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, recognized, err := parseGetConfRequest([]byte(tc.packet))
			if recognized != tc.recognized {
				t.Fatalf("recognized = %v, want %v", recognized, tc.recognized)
			}
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tc.wantErr)
			}
			if err == nil && got != tc.want {
				t.Fatalf("request = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func FuzzObfsUnwrap(f *testing.F) {
	validWire, err := hex.DecodeString(compatWireHex)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(validWire)
	f.Add([]byte{})
	f.Add([]byte{0x80, 0x6f})

	key, err := deriveWrapKey(compatPassword)
	if err != nil {
		f.Fatal(err)
	}
	aead, err := getAEAD(key)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > 4096 {
			return
		}
		out := make([]byte, 4096)
		_, _ = obfsUnwrapPacketAEAD(aead, wire, out)
	})
}

func FuzzGetConfRequest(f *testing.F) {
	f.Add([]byte("GETCONF:9000|device-0001|Strong-Test_7kM9xQ2"))
	f.Add([]byte("READY"))
	f.Add([]byte("GETCONF:"))
	f.Fuzz(func(t *testing.T, packet []byte) {
		if len(packet) > 2048 {
			return
		}
		req, recognized, err := parseGetConfRequest(packet)
		if !recognized || err != nil {
			return
		}
		port, convErr := strconv.Atoi(req.ClientPort)
		if convErr != nil || port < 1 || port > 65535 {
			t.Fatalf("parser returned invalid port %q", req.ClientPort)
		}
		if req.DeviceID == "" || req.Password == "" {
			t.Fatal("parser returned an empty required field")
		}
	})
}
