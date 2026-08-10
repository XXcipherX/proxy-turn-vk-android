package main

import (
	"bytes"
	"encoding/hex"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
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
		{
			name:       "valid lifecycle v2 shape",
			packet:     "GETCONF:9000|android-device|Strong-Test_7kM9xQ2|550e8400-e29b-41d4-a716-446655440000|27",
			recognized: true,
			want: getConfRequest{
				ClientPort:   "9000",
				DeviceID:     "android-device",
				Password:     "Strong-Test_7kM9xQ2",
				GenerationID: "550e8400-e29b-41d4-a716-446655440000",
				WorkerID:     "27",
			},
		},
		{name: "not GETCONF", packet: "READY"},
		{name: "missing password", packet: "GETCONF:9000|device", recognized: true, wantErr: true},
		{name: "extra field", packet: "GETCONF:9000|device|secret|extra", recognized: true, wantErr: true},
		{name: "missing worker ID", packet: "GETCONF:9000|device|secret|generation|", recognized: true, wantErr: true},
		{name: "invalid generation ID", packet: "GETCONF:9000|device|secret|generation/unsafe|worker", recognized: true, wantErr: true},
		{name: "invalid worker ID", packet: "GETCONF:9000|device|secret|generation|worker/unsafe", recognized: true, wantErr: true},
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

func TestRelayKeepaliveRecognition(t *testing.T) {
	tests := []struct {
		name   string
		packet []byte
		want   bool
	}{
		{name: "iOS zero byte", packet: []byte{0x00}, want: true},
		{name: "Android ff byte", packet: []byte{0xFF}, want: true},
		{name: "other single byte", packet: []byte{0x01}},
		{name: "WireGuard payload", packet: []byte{0x00, 0x01}},
		{name: "empty", packet: nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isRelayKeepalive(tc.packet); got != tc.want {
				t.Fatalf("isRelayKeepalive(%x) = %v, want %v", tc.packet, got, tc.want)
			}
		})
	}
}

func TestInitialRelayPacketDeadlineIsAbsolute(t *testing.T) {
	conn := &relayDeadlineConn{packets: [][]byte{
		{0x00},
		{0xFF},
		[]byte("GETCONF:51820|device|password"),
	}}
	packet, err := readInitialRelayPacket(conn, make([]byte, 128), 30*time.Second)
	if err != nil {
		t.Fatalf("readInitialRelayPacket: %v", err)
	}
	if string(packet) != "GETCONF:51820|device|password" {
		t.Fatalf("packet = %q", packet)
	}
	if len(conn.deadlines) != len(conn.packets) {
		t.Fatalf("deadlines = %d, want %d", len(conn.deadlines), len(conn.packets))
	}
	for i := 1; i < len(conn.deadlines); i++ {
		if !conn.deadlines[i].Equal(conn.deadlines[0]) {
			t.Fatalf("deadline %d changed from %v to %v", i, conn.deadlines[0], conn.deadlines[i])
		}
	}
}

type relayDeadlineConn struct {
	packets   [][]byte
	readIndex int
	deadlines []time.Time
}

func (c *relayDeadlineConn) Read(p []byte) (int, error) {
	if c.readIndex >= len(c.packets) {
		return 0, io.EOF
	}
	packet := c.packets[c.readIndex]
	c.readIndex++
	return copy(p, packet), nil
}

func (c *relayDeadlineConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *relayDeadlineConn) Close() error                { return nil }
func (c *relayDeadlineConn) LocalAddr() net.Addr         { return nil }
func (c *relayDeadlineConn) RemoteAddr() net.Addr        { return nil }
func (c *relayDeadlineConn) SetDeadline(time.Time) error { return nil }
func (c *relayDeadlineConn) SetReadDeadline(deadline time.Time) error {
	c.deadlines = append(c.deadlines, deadline)
	return nil
}
func (c *relayDeadlineConn) SetWriteDeadline(time.Time) error { return nil }

func TestRelayIdleTimeoutSelection(t *testing.T) {
	timeouts := relayIdleTimeouts{
		legacy:      3 * time.Minute,
		lifecycleV2: 30 * time.Minute,
	}

	if got := timeouts.forRequest(getConfRequest{}); got != timeouts.legacy {
		t.Fatalf("legacy timeout = %s, want %s", got, timeouts.legacy)
	}
	if got := timeouts.forRequest(getConfRequest{GenerationID: "generation", WorkerID: "worker"}); got != timeouts.lifecycleV2 {
		t.Fatalf("lifecycle v2 timeout = %s, want %s", got, timeouts.lifecycleV2)
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
		if (req.GenerationID == "") != (req.WorkerID == "") {
			t.Fatal("parser returned a partial lifecycle identity")
		}
	})
}
