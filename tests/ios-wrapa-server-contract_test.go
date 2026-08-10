package proxy

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
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

// TestServerCompatibilityClientWrite verifies the opposite wire direction:
// a packet emitted by the current iOS client must be accepted by an
// independent implementation of the server-side WRAP-A decoder.
func TestServerCompatibilityClientWrite(t *testing.T) {
	const password = "WDTT-Compat-Vector-01"
	payload := []byte("iOS client to WDTT server")
	key, err := deriveWrapAKey(password)
	if err != nil {
		t.Fatalf("deriveWrapAKey: %v", err)
	}
	base := &serverContractPacketConn{}
	remote := serverContractAddr("wdtt-server")
	connection, err := newWrapAPacketConn(base, remote, key)
	if err != nil {
		t.Fatalf("newWrapAPacketConn: %v", err)
	}
	n, err := connection.WriteTo(payload, remote)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("WriteTo length = %d, want %d", n, len(payload))
	}
	plain, err := serverContractUnwrap(key, base.wire)
	if err != nil {
		t.Fatalf("server-side unwrap: %v", err)
	}
	if !bytes.Equal(plain, payload) {
		t.Fatalf("plaintext = %q, want %q", plain, payload)
	}
}

// TestServerCompatibilityServerPacketVariants covers the server's normal
// unpadded packet without the optional RTP marker bit. The golden vector
// above already covers a padded packet with the marker bit.
func TestServerCompatibilityServerPacketVariants(t *testing.T) {
	key, err := deriveWrapAKey("WDTT-Compat-Vector-01")
	if err != nil {
		t.Fatalf("deriveWrapAKey: %v", err)
	}
	payload := []byte("unpadded server packet")
	wire := serverContractWrap(t, key, payload, false)
	connection, err := newWrapAPacketConn(nil, nil, key)
	if err != nil {
		t.Fatalf("newWrapAPacketConn: %v", err)
	}
	out := make([]byte, 256)
	n, err := connection.wrapAUnwrap(wire, out)
	if err != nil {
		t.Fatalf("unwrap unpadded server packet: %v", err)
	}
	if !bytes.Equal(out[:n], payload) {
		t.Fatalf("plaintext = %q, want %q", out[:n], payload)
	}
}

// TestServerCompatibilityGetconf checks the legacy three-field request used
// by iOS and parsing of the WireGuard INI returned by this server.
func TestServerCompatibilityGetconf(t *testing.T) {
	const (
		deviceID = "ios-contract-device"
		password = "WDTT-Compat-Vector-01"
	)
	privateKey := bytes.Repeat([]byte{0x11}, 32)
	publicKey := bytes.Repeat([]byte{0x22}, 32)
	response := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.66.66.42/32
DNS = 9.9.9.9, 1.1.1.1
MTU = 1280

[Peer]
PublicKey = %s
Endpoint = 127.0.0.1:51820
PersistentKeepalive = 25
`, base64.StdEncoding.EncodeToString(privateKey), base64.StdEncoding.EncodeToString(publicKey))

	client, server := net.Pipe()
	defer client.Close()
	requestCh := make(chan string, 1)
	serverErrCh := make(chan error, 1)
	go func() {
		defer server.Close()
		buf := make([]byte, 1024)
		n, err := server.Read(buf)
		if err != nil {
			serverErrCh <- err
			return
		}
		requestCh <- string(buf[:n])
		_, err = server.Write([]byte(response))
		serverErrCh <- err
	}()

	provision, err := doGetconf(client, deviceID, password)
	if err != nil {
		t.Fatalf("doGetconf: %v", err)
	}
	if err := <-serverErrCh; err != nil {
		t.Fatalf("fixture server: %v", err)
	}
	request := <-requestCh
	fields := strings.Split(strings.TrimPrefix(request, "GETCONF:"), "|")
	if !strings.HasPrefix(request, "GETCONF:") || len(fields) != 3 {
		t.Fatalf("request = %q, want legacy three-field GETCONF", request)
	}
	port, err := strconv.Atoi(fields[0])
	if err != nil || port < 1 || port > 65535 {
		t.Fatalf("GETCONF port = %q", fields[0])
	}
	if fields[1] != deviceID || fields[2] != password {
		t.Fatalf("GETCONF identity = %q|%q", fields[1], fields[2])
	}
	if provision.PrivateKeyHex != hex.EncodeToString(privateKey) {
		t.Fatalf("private key = %s", provision.PrivateKeyHex)
	}
	if provision.PeerPublicKeyHex != hex.EncodeToString(publicKey) {
		t.Fatalf("public key = %s", provision.PeerPublicKeyHex)
	}
	if provision.Address != "10.66.66.42/32" || provision.DNS != "9.9.9.9" || provision.MTU != 1280 || provision.KeepaliveSec != 25 {
		t.Fatalf("parsed provision = %+v", provision)
	}
}

type serverContractAddr string

func (a serverContractAddr) Network() string { return "udp" }
func (a serverContractAddr) String() string  { return string(a) }

type serverContractPacketConn struct {
	wire []byte
}

func (c *serverContractPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, io.EOF
}

func (c *serverContractPacketConn) WriteTo(packet []byte, _ net.Addr) (int, error) {
	c.wire = append(c.wire[:0], packet...)
	return len(packet), nil
}

func (c *serverContractPacketConn) Close() error                     { return nil }
func (c *serverContractPacketConn) LocalAddr() net.Addr              { return serverContractAddr("local") }
func (c *serverContractPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *serverContractPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *serverContractPacketConn) SetWriteDeadline(time.Time) error { return nil }

func serverContractUnwrap(key, wire []byte) ([]byte, error) {
	if len(wire) <= 12+chacha20poly1305.Overhead || wire[0]>>6 != 2 || wire[1]&0x7f != 111 {
		return nil, fmt.Errorf("invalid RTP envelope")
	}
	payloadEnd := len(wire)
	if wire[0]&0x20 != 0 {
		padding := int(wire[len(wire)-1])
		if padding == 0 || padding > payloadEnd-12 {
			return nil, fmt.Errorf("invalid RTP padding %d", padding)
		}
		payloadEnd -= padding
	}
	if payloadEnd <= 12+chacha20poly1305.Overhead {
		return nil, fmt.Errorf("empty encrypted payload")
	}
	var nonce [12]byte
	binary.BigEndian.PutUint32(nonce[0:4], binary.BigEndian.Uint32(wire[8:12]))
	binary.BigEndian.PutUint16(nonce[4:6], binary.BigEndian.Uint16(wire[2:4]))
	binary.BigEndian.PutUint32(nonce[8:12], binary.BigEndian.Uint32(wire[4:8]))
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce[:], wire[12:payloadEnd], wire[:12])
}

func serverContractWrap(t *testing.T, key, payload []byte, marker bool) []byte {
	t.Helper()
	wire := make([]byte, 12, 12+len(payload)+chacha20poly1305.Overhead)
	wire[0] = 0x80
	wire[1] = 111
	if marker {
		wire[1] |= 0x80
	}
	binary.BigEndian.PutUint16(wire[2:4], 0x5566)
	binary.BigEndian.PutUint32(wire[4:8], 0x778899aa)
	binary.BigEndian.PutUint32(wire[8:12], 0x11223344)
	var nonce [12]byte
	binary.BigEndian.PutUint32(nonce[0:4], 0x11223344)
	binary.BigEndian.PutUint16(nonce[4:6], 0x5566)
	binary.BigEndian.PutUint32(nonce[8:12], 0x778899aa)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatalf("server fixture AEAD: %v", err)
	}
	return aead.Seal(wire, nonce[:], payload, wire[:12])
}
