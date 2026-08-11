

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func testKey(t testing.TB, password string) []byte {
	t.Helper()
	k, err := deriveWrapKey(password)
	if err != nil {
		t.Fatalf("deriveWrapKey: %v", err)
	}
	return k
}

func randPayload(t testing.TB, n int) []byte {
	t.Helper()
	p := make([]byte, n)
	if _, err := rand.Read(p); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return p
}

func TestObfsBuildNonceEquiv(t *testing.T) {
	cases := []struct {
		ssrc uint32
		seq  uint16
		ts   uint32
	}{
		{0, 0, 0},
		{0xDEADBEEF, 0x1234, 0xCAFEBABE},
		{1, 65535, 0xFFFFFFFF},
	}
	for _, c := range cases {
		want := obfsBuildNonce(c.ssrc, c.seq, c.ts)
		var got [12]byte
		obfsBuildNonceInto(&got, c.ssrc, c.seq, c.ts)
		if !bytes.Equal(want, got[:]) {
			t.Errorf("nonce mismatch ssrc=%x seq=%x ts=%x: want %x got %x",
				c.ssrc, c.seq, c.ts, want, got[:])
		}
		
		if got[6] != 0 || got[7] != 0 {
			t.Errorf("nonce [6:8] not zero: %x", got[:])
		}
	}
}

func TestObfsRoundTrip(t *testing.T) {
	key := testKey(t, "round-trip-pass")
	aead, err := getAEAD(key)
	if err != nil {
		t.Fatalf("getAEAD: %v", err)
	}
	cfg := NewObfsConfig()
	state := NewObfsState()

	for _, n := range []int{1, 13, 64, 100, 1000, 1280, 1400} {
		payload := randPayload(t, n)
		dst := make([]byte, obfsWrapWireLen(n, cfg))
		wn, err := obfsWrapPacketInto(dst, aead, payload, cfg, state)
		if err != nil {
			t.Fatalf("wrap n=%d: %v", n, err)
		}
		wire := dst[:wn]

		
		if wire[0]>>6 != 2 {
			t.Errorf("n=%d byte0=%#x, want RTP v2", n, wire[0])
		}
		if wire[1]&0x7F != 111 {
			t.Errorf("n=%d PT=%d, want 111", n, wire[1]&0x7F)
		}
		if !obfsIsRTPPacket(wire) {
			t.Errorf("n=%d: obfsIsRTPPacket=false", n)
		}

		out := make([]byte, n+64)
		m, err := obfsUnwrapPacketAEAD(aead, wire, out)
		if err != nil {
			t.Fatalf("unwrap n=%d: %v", n, err)
		}
		if !bytes.Equal(out[:m], payload) {
			t.Errorf("n=%d: payload mismatch after round trip", n)
		}
	}
}

func TestObfsRTPMetadataSelectors(t *testing.T) {
	if !useRTPPadding(0) || useRTPPadding(1) {
		t.Fatal("padding selector does not vary the RTP padding bit")
	}
	if !useRTPMarker(0) || useRTPMarker(1) {
		t.Fatal("marker selector does not vary the RTP marker bit")
	}
	if rtpSequenceStep(1) != 1 || rtpSequenceStep(0) == 1 {
		t.Fatal("sequence selector does not introduce occasional gaps")
	}
	steps := map[uint32]struct{}{
		rtpTimestampStep(20*time.Millisecond, 0): struct{}{},
		rtpTimestampStep(20*time.Millisecond, 1): struct{}{},
		rtpTimestampStep(20*time.Millisecond, 2): struct{}{},
	}
	if len(steps) != 3 {
		t.Fatalf("timestamp jitter did not produce distinct steps: %v", steps)
	}
}

func TestObfsWireCompatOldNew(t *testing.T) {
	key := testKey(t, "compat-pass")
	aead, err := getAEAD(key)
	if err != nil {
		t.Fatalf("getAEAD: %v", err)
	}
	payload := randPayload(t, 512)

	
	{
		cfg := NewObfsConfig()
		state := NewObfsState()
		wire, err := obfsWrapPacket(key, payload, cfg, state)
		if err != nil {
			t.Fatalf("old wrap: %v", err)
		}
		out := make([]byte, len(payload)+64)
		m, err := obfsUnwrapPacketAEAD(aead, wire, out)
		if err != nil {
			t.Fatalf("new unwrap of old wrap: %v", err)
		}
		if !bytes.Equal(out[:m], payload) {
			t.Fatal("old->new payload mismatch")
		}
	}

	
	{
		cfg := NewObfsConfig()
		state := NewObfsState()
		dst := make([]byte, obfsWrapWireLen(len(payload), cfg))
		n, err := obfsWrapPacketInto(dst, aead, payload, cfg, state)
		if err != nil {
			t.Fatalf("new wrap: %v", err)
		}
		out := make([]byte, len(payload)+64)
		m, err := obfsUnwrapPacket(key, dst[:n], out)
		if err != nil {
			t.Fatalf("old unwrap of new wrap: %v", err)
		}
		if !bytes.Equal(out[:m], payload) {
			t.Fatal("new->old payload mismatch")
		}
	}
}

func TestObfsWrongKeyFails(t *testing.T) {
	aeadA, _ := getAEAD(testKey(t, "alice"))
	aeadB, _ := getAEAD(testKey(t, "bob"))
	cfg := NewObfsConfig()
	state := NewObfsState()
	payload := randPayload(t, 200)

	dst := make([]byte, obfsWrapWireLen(len(payload), cfg))
	n, err := obfsWrapPacketInto(dst, aeadA, payload, cfg, state)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	out := make([]byte, len(payload)+64)
	if _, err := obfsUnwrapPacketAEAD(aeadB, dst[:n], out); err == nil {
		t.Fatal("expected auth failure with wrong key, got nil")
	}
}

func TestObfsWrapDstTooSmall(t *testing.T) {
	aead, _ := getAEAD(testKey(t, "small"))
	cfg := NewObfsConfig()
	state := NewObfsState()
	payload := randPayload(t, 500)
	tiny := make([]byte, 50)
	if _, err := obfsWrapPacketInto(tiny, aead, payload, cfg, state); err == nil {
		t.Fatal("expected error for too-small dst")
	}
}

func TestWrapKeyStoreUnwrapSelectsKey(t *testing.T) {
	ks := newWrapKeyStore()
	if err := ks.SetPasswords("main-pw", []string{"gen-pw-1", "gen-pw-2"}); err != nil {
		t.Fatalf("SetPasswords: %v", err)
	}

	for _, pw := range []string{"main-pw", "gen-pw-1", "gen-pw-2"} {
		key := testKey(t, pw)
		aead, _ := getAEAD(key)
		cfg := NewObfsConfig()
		state := NewObfsState()
		payload := randPayload(t, 128)
		dst := make([]byte, obfsWrapWireLen(len(payload), cfg))
		n, _ := obfsWrapPacketInto(dst, aead, payload, cfg, state)

		out := make([]byte, len(payload)+64)
		gotKey, identity, m, err := ks.Unwrap(dst[:n], out)
		if err != nil {
			t.Fatalf("pw=%s Unwrap: %v", pw, err)
		}
		if !bytes.Equal(gotKey, key) {
			t.Errorf("pw=%s: store selected wrong key", pw)
		}
		if identity.Password != pw || identity.IsMain != (pw == "main-pw") {
			t.Errorf("pw=%s: wrong identity: %+v", pw, identity)
		}
		if !bytes.Equal(out[:m], payload) {
			t.Errorf("pw=%s: payload mismatch", pw)
		}
	}

	
	badKey := testKey(t, "not-registered")
	badAead, _ := getAEAD(badKey)
	cfg := NewObfsConfig()
	state := NewObfsState()
	dst := make([]byte, obfsWrapWireLen(16, cfg))
	n, _ := obfsWrapPacketInto(dst, badAead, randPayload(t, 16), cfg, state)
	out := make([]byte, 128)
	if _, _, _, err := ks.Unwrap(dst[:n], out); err == nil {
		t.Fatal("expected Unwrap failure for unregistered password")
	}
}

func testDTLSClientHello() []byte {
	payload := make([]byte, 13+12+38)
	payload[0] = 22
	payload[1] = 0xfe
	payload[2] = 0xfd
	binary.BigEndian.PutUint16(payload[11:13], uint16(len(payload)-13))
	payload[13] = 1
	payload[16] = 38
	payload[24] = 38
	return payload
}

func TestAcceptWrappedPacketAuthenticatesBeforeAdmission(t *testing.T) {
	const password = "admission-main-password"
	keys := newWrapKeyStore()
	if err := keys.SetPasswords(password, nil); err != nil {
		t.Fatalf("SetPasswords: %v", err)
	}

	key := testKey(t, password)
	aead, err := getAEAD(key)
	if err != nil {
		t.Fatalf("getAEAD: %v", err)
	}
	payload := testDTLSClientHello()
	wire := make([]byte, obfsWrapWireLen(len(payload), NewObfsConfig()))
	n, err := obfsWrapPacketInto(wire, aead, payload, NewObfsConfig(), NewObfsState())
	if err != nil {
		t.Fatalf("wrap valid packet: %v", err)
	}
	if !acceptWrappedPacket(keys, wire[:n]) {
		t.Fatal("authenticated WRAP packet was rejected")
	}

	nonClientHello := append([]byte(nil), payload...)
	nonClientHello[13] = 2
	nonHelloWire := make([]byte, obfsWrapWireLen(len(nonClientHello), NewObfsConfig()))
	nonHelloN, err := obfsWrapPacketInto(nonHelloWire, aead, nonClientHello, NewObfsConfig(), NewObfsState())
	if err != nil {
		t.Fatalf("wrap non-ClientHello packet: %v", err)
	}

	badRTP := append([]byte(nil), wire[:n]...)
	badRTP[len(badRTP)-1] ^= 0xff
	for name, packet := range map[string][]byte{
		"raw DTLS":      {0x16, 0xfe, 0xfd, 0x00},
		"forged RTP":    badRTP,
		"non ClientHello": nonHelloWire[:nonHelloN],
		"empty packet":  {},
		"oversized RTP": append([]byte{0x80, 0x6f}, make([]byte, maxWrappedPacketSize)...),
	} {
		t.Run(name, func(t *testing.T) {
			if acceptWrappedPacket(keys, packet) {
				t.Fatal("unauthenticated datagram passed the admission filter")
			}
		})
	}

	replayCache := newWrapReplayCache()
	if !acceptWrappedPacketOnce(keys, replayCache, wire[:n]) || acceptWrappedPacketOnce(keys, replayCache, wire[:n]) {
		t.Fatal("first WRAP packet replay was not rejected")
	}
}

func TestWrapPacketConnPrimeSelectsIdentityAndReplaysClientHello(t *testing.T) {
	const password = "prime-identity-password"
	keys := newWrapKeyStore()
	if err := keys.SetPasswords(password, nil); err != nil {
		t.Fatalf("SetPasswords: %v", err)
	}
	clientRaw, serverRaw := newFakePair()
	server := &wrapPacketConn{inner: serverRaw, keys: keys}

	key := testKey(t, password)
	aead, err := getAEAD(key)
	if err != nil {
		t.Fatalf("getAEAD: %v", err)
	}
	clientHello := testDTLSClientHello()
	cfg := NewObfsConfig()
	wire := make([]byte, obfsWrapWireLen(len(clientHello), cfg))
	n, err := obfsWrapPacketInto(wire, aead, clientHello, cfg, NewObfsState())
	if err != nil {
		t.Fatalf("wrap ClientHello: %v", err)
	}
	if _, err := clientRaw.WriteTo(wire[:n], clientRaw.remote); err != nil {
		t.Fatalf("write ClientHello: %v", err)
	}
	if err := server.prime(); err != nil {
		t.Fatalf("prime: %v", err)
	}
	identity, ok := server.Identity()
	if !ok || !identity.IsMain || identity.Password != password {
		t.Fatalf("identity = %+v, %v", identity, ok)
	}
	got := make([]byte, maxWrappedPacketSize)
	gotN, _, err := server.ReadFrom(got)
	if err != nil {
		t.Fatalf("read primed packet: %v", err)
	}
	if !bytes.Equal(got[:gotN], clientHello) {
		t.Fatal("primed ClientHello was not replayed unchanged")
	}
}

type fakeAddr string

func (fakeAddr) Network() string  { return "fake" }
func (a fakeAddr) String() string { return string(a) }

type fakePacketConn struct {
	rx     chan []byte
	tx     chan []byte
	local  fakeAddr
	remote fakeAddr
	once   sync.Once
}

func newFakePair() (*fakePacketConn, *fakePacketConn) {
	a2b := make(chan []byte, 32)
	b2a := make(chan []byte, 32)
	a := &fakePacketConn{rx: b2a, tx: a2b, local: "A", remote: "B"}
	b := &fakePacketConn{rx: a2b, tx: b2a, local: "B", remote: "A"}
	return a, b
}

func (c *fakePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	pkt, ok := <-c.rx
	if !ok {
		return 0, c.remote, io.EOF
	}
	return copy(p, pkt), c.remote, nil
}

func (c *fakePacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	b := make([]byte, len(p))
	copy(b, p)
	c.tx <- b
	return len(p), nil
}

func (c *fakePacketConn) Close() error                     { c.once.Do(func() { close(c.tx) }); return nil }
func (c *fakePacketConn) LocalAddr() net.Addr              { return c.local }
func (c *fakePacketConn) SetDeadline(time.Time) error      { return nil }
func (c *fakePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakePacketConn) SetWriteDeadline(time.Time) error { return nil }

type staticPacketConn struct {
	packet []byte
	addr   net.Addr
}

func (c *staticPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	return copy(p, c.packet), c.addr, nil
}

func (c *staticPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (c *staticPacketConn) Close() error                              { return nil }
func (c *staticPacketConn) LocalAddr() net.Addr                       { return fakeAddr("server") }
func (c *staticPacketConn) SetDeadline(time.Time) error               { return nil }
func (c *staticPacketConn) SetReadDeadline(time.Time) error           { return nil }
func (c *staticPacketConn) SetWriteDeadline(time.Time) error          { return nil }

func TestWrapPacketConnEndToEnd(t *testing.T) {
	const pw = "e2e-main"
	ks := newWrapKeyStore()
	if err := ks.SetPasswords(pw, nil); err != nil {
		t.Fatalf("SetPasswords: %v", err)
	}
	clientRaw, serverRaw := newFakePair()
	server := &wrapPacketConn{inner: serverRaw, keys: ks}

	key := testKey(t, pw)
	clientAead, _ := getAEAD(key)
	clientCfg := NewObfsConfig()
	clientState := NewObfsState()

	clientSend := func(payload []byte) {
		dst := make([]byte, obfsWrapWireLen(len(payload), clientCfg))
		n, err := obfsWrapPacketInto(dst, clientAead, payload, clientCfg, clientState)
		if err != nil {
			t.Fatalf("client wrap: %v", err)
		}
		if _, err := clientRaw.WriteTo(dst[:n], clientRaw.remote); err != nil {
			t.Fatalf("client write: %v", err)
		}
	}

	
	first := []byte("GETCONF:51820|deadbeef|" + pw)
	clientSend(first)
	rbuf := make([]byte, 2048)
	n, _, err := server.ReadFrom(rbuf)
	if err != nil {
		t.Fatalf("server ReadFrom (select): %v", err)
	}
	if !bytes.Equal(rbuf[:n], first) {
		t.Fatalf("first payload mismatch: got %q", rbuf[:n])
	}

	
	
	resp := randPayload(t, 800)
	if _, err := server.WriteTo(resp, serverRaw.remote); err != nil {
		t.Fatalf("server WriteTo: %v", err)
	}
	wire := make([]byte, 2048)
	wn, _, err := clientRaw.ReadFrom(wire)
	if err != nil {
		t.Fatalf("client ReadFrom: %v", err)
	}
	cout := make([]byte, 2048)
	cm, err := obfsUnwrapPacketAEAD(clientAead, wire[:wn], cout)
	if err != nil {
		t.Fatalf("client unwrap server resp: %v", err)
	}
	if !bytes.Equal(cout[:cm], resp) {
		t.Fatal("server->client payload mismatch")
	}

	
	for i := 0; i < 50; i++ {
		msg := randPayload(t, 200+i)
		clientSend(msg)
		rn, _, err := server.ReadFrom(rbuf)
		if err != nil {
			t.Fatalf("server ReadFrom #%d: %v", i, err)
		}
		if !bytes.Equal(rbuf[:rn], msg) {
			t.Fatalf("client->server payload mismatch #%d", i)
		}
	}
}

func TestWrapPacketConnSkipsCorruptDatagramAfterKeySelection(t *testing.T) {
	const password = "selected-session-password"
	keys := newWrapKeyStore()
	if err := keys.SetPasswords(password, nil); err != nil {
		t.Fatalf("SetPasswords: %v", err)
	}
	clientRaw, serverRaw := newFakePair()
	server := &wrapPacketConn{inner: serverRaw, keys: keys}

	key := testKey(t, password)
	aead, err := getAEAD(key)
	if err != nil {
		t.Fatalf("getAEAD: %v", err)
	}
	config := NewObfsConfig()
	state := NewObfsState()
	wrap := func(payload []byte) []byte {
		dst := make([]byte, obfsWrapWireLen(len(payload), config))
		n, wrapErr := obfsWrapPacketInto(dst, aead, payload, config, state)
		if wrapErr != nil {
			t.Fatalf("wrap: %v", wrapErr)
		}
		return dst[:n]
	}

	first := wrap([]byte("GETCONF:51820|selected-device|" + password))
	if _, err := clientRaw.WriteTo(first, clientRaw.remote); err != nil {
		t.Fatalf("write first packet: %v", err)
	}
	readBuffer := make([]byte, 2048)
	if _, _, err := server.ReadFrom(readBuffer); err != nil {
		t.Fatalf("select key: %v", err)
	}

	corrupt := append([]byte(nil), wrap([]byte("corrupt me"))...)
	corrupt[len(corrupt)-1] ^= 0xff
	if _, err := clientRaw.WriteTo(corrupt, clientRaw.remote); err != nil {
		t.Fatalf("write corrupt packet: %v", err)
	}
	want := []byte("valid packet after corruption")
	if _, err := clientRaw.WriteTo(wrap(want), clientRaw.remote); err != nil {
		t.Fatalf("write valid packet: %v", err)
	}
	n, _, err := server.ReadFrom(readBuffer)
	if err != nil {
		t.Fatalf("read after corrupt packet: %v", err)
	}
	if !bytes.Equal(readBuffer[:n], want) {
		t.Fatalf("payload = %q, want %q", readBuffer[:n], want)
	}
}

const obfsHotPathMaxAllocs = 1.0

func TestObfsHotPathAllocsBounded(t *testing.T) {
	if raceEnabled {
		t.Skip("race instrumentation distorts allocation counts")
	}
	key := testKey(t, "alloc-pass")
	aead, _ := getAEAD(key)
	cfg := NewObfsConfig()
	state := NewObfsState()
	payload := randPayload(t, 1200)
	dst := make([]byte, obfsWrapWireLen(len(payload), cfg))
	out := make([]byte, len(payload)+64)

	wrapAllocs := testing.AllocsPerRun(200, func() {
		if _, err := obfsWrapPacketInto(dst, aead, payload, cfg, state); err != nil {
			t.Fatal(err)
		}
	})
	if wrapAllocs > obfsHotPathMaxAllocs {
		t.Errorf("obfsWrapPacketInto: %.1f allocs/op, want <= %.0f", wrapAllocs, obfsHotPathMaxAllocs)
	}
	var wrapNonce [wrapNonceLen]byte
	wrapScratchAllocs := testing.AllocsPerRun(200, func() {
		if _, err := obfsWrapPacketIntoWithNonce(dst, aead, payload, cfg, state, &wrapNonce); err != nil {
			t.Fatal(err)
		}
	})
	if wrapScratchAllocs != 0 {
		t.Errorf("obfsWrapPacketIntoWithNonce: %.1f allocs/op, want 0", wrapScratchAllocs)
	}

	
	wn, _ := obfsWrapPacketInto(dst, aead, payload, cfg, state)
	wire := append([]byte(nil), dst[:wn]...)
	unwrapAllocs := testing.AllocsPerRun(200, func() {
		if _, err := obfsUnwrapPacketAEAD(aead, wire, out); err != nil {
			t.Fatal(err)
		}
	})
	if unwrapAllocs > obfsHotPathMaxAllocs {
		t.Errorf("obfsUnwrapPacketAEAD: %.1f allocs/op, want <= %.0f", unwrapAllocs, obfsHotPathMaxAllocs)
	}
	var unwrapNonce [wrapNonceLen]byte
	unwrapScratchAllocs := testing.AllocsPerRun(200, func() {
		if _, err := obfsUnwrapPacketAEADWithNonce(aead, wire, out, &unwrapNonce); err != nil {
			t.Fatal(err)
		}
	})
	if unwrapScratchAllocs != 0 {
		t.Errorf("obfsUnwrapPacketAEADWithNonce: %.1f allocs/op, want 0", unwrapScratchAllocs)
	}

	
	
	oldAllocs := testing.AllocsPerRun(200, func() {
		if _, err := obfsWrapPacket(key, payload, cfg, state); err != nil {
			t.Fatal(err)
		}
	})
	if wrapAllocs >= oldAllocs {
		t.Errorf("new wrap (%.1f allocs) not better than old (%.1f allocs)", wrapAllocs, oldAllocs)
	}
}

func TestWrapPacketConnReadAllocsBounded(t *testing.T) {
	if raceEnabled {
		t.Skip("race instrumentation distorts allocation counts")
	}
	key := testKey(t, "packet-conn-alloc-pass")
	aead, err := getAEAD(key)
	if err != nil {
		t.Fatalf("getAEAD: %v", err)
	}
	payload := randPayload(t, 1200)
	cfg := NewObfsConfig()
	wire := make([]byte, obfsWrapWireLen(len(payload), cfg))
	wn, err := obfsWrapPacketInto(wire, aead, payload, cfg, NewObfsState())
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	conn := &wrapPacketConn{
		inner:    &staticPacketConn{packet: wire[:wn], addr: fakeAddr("client")},
		aead:     aead,
		selected: 1,
	}
	out := make([]byte, len(payload))

	allocs := testing.AllocsPerRun(200, func() {
		n, _, readErr := conn.ReadFrom(out)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if n != len(payload) {
			t.Fatalf("ReadFrom length = %d, want %d", n, len(payload))
		}
	})
	if allocs != 0 {
		t.Errorf("wrapPacketConn.ReadFrom: %.1f allocs/op, want 0", allocs)
	}
}

func BenchmarkObfsWrapInto(b *testing.B) {
	key := testKey(b, "bench")
	aead, _ := getAEAD(key)
	cfg := NewObfsConfig()
	state := NewObfsState()
	payload := randPayload(b, 1200)
	dst := make([]byte, obfsWrapWireLen(len(payload), cfg))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := obfsWrapPacketInto(dst, aead, payload, cfg, state); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkObfsWrapOldAllocating(b *testing.B) {
	key := testKey(b, "bench")
	cfg := NewObfsConfig()
	state := NewObfsState()
	payload := randPayload(b, 1200)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := obfsWrapPacket(key, payload, cfg, state); err != nil {
			b.Fatal(err)
		}
	}
}
