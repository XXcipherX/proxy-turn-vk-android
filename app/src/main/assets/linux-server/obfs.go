package main

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	pionudp "github.com/pion/transport/v4/udp"
)

const (
	wrapNonceLen         = 12
	wrapKeyLen           = 32
	maxWrappedPacketSize = 2048
	wrappedSocketBuffer  = 4 * 1024 * 1024
	wrappedListenBacklog = 512
	wrapReplayCacheSize  = 4096
	wrapReplayTTL        = 30 * time.Second
)

var (
	aeadCacheMu sync.RWMutex
	aeadCache   = make(map[string]cipher.AEAD)
)

func getAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != wrapKeyLen {
		return nil, fmt.Errorf("obfs: key must be %d bytes", wrapKeyLen)
	}
	keyStr := string(key)

	aeadCacheMu.RLock()
	if aead, ok := aeadCache[keyStr]; ok {
		aeadCacheMu.RUnlock()
		return aead, nil
	}
	aeadCacheMu.RUnlock()

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	aeadCacheMu.Lock()
	aeadCache[keyStr] = aead
	aeadCacheMu.Unlock()
	return aead, nil
}

type ObfsConfig struct {
	SSRC        uint32
	PayloadType uint8
	PaddingMax  int
}

type ObfsState struct {
	mu         sync.Mutex
	seq        uint16
	timestamp  uint32
	lastPacket time.Time
	count      uint64
}

func NewObfsConfig() *ObfsConfig {
	var buf [4]byte
	_, _ = rand.Read(buf[:])
	return &ObfsConfig{
		SSRC:        binary.BigEndian.Uint32(buf[:]),
		PayloadType: 111,
		PaddingMax:  24,
	}
}

func NewObfsState() *ObfsState {
	var buf [6]byte
	_, _ = rand.Read(buf[:])
	return &ObfsState{
		seq:       binary.BigEndian.Uint16(buf[0:2]),
		timestamp: binary.BigEndian.Uint32(buf[2:6]),
	}
}

func rtpTimestampStep(elapsed time.Duration, jitter byte) uint32 {
	samples := int64(elapsed) * 48000 / int64(time.Second)
	if samples < 120 {
		samples = 120
	} else if samples > 2880 {
		samples = 2880
	}
	samples = ((samples + 60) / 120) * 120
	samples += int64(int(jitter)%3-1) * 120
	if samples < 120 {
		samples = 120
	} else if samples > 2880 {
		samples = 2880
	}
	return uint32(samples)
}

func rtpSequenceStep(selector byte) uint16 {
	if selector&0x7F == 0 {
		return 2 + uint16(selector>>7)
	}
	return 1
}

func (s *ObfsState) nextHeader(now time.Time, jitter, sequenceSelector byte) (uint16, uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	seq := s.seq
	if s.count > 0 {
		s.timestamp += rtpTimestampStep(now.Sub(s.lastPacket), jitter)
	}
	timestamp := s.timestamp
	s.seq += rtpSequenceStep(sequenceSelector)
	s.lastPacket = now
	s.count++
	return seq, timestamp
}

func useRTPPadding(selector byte) bool {
	return selector&0x03 == 0
}

func useRTPMarker(selector byte) bool {
	return selector&0x3F == 0
}

func obfsBuildNonceInto(dst *[12]byte, ssrc uint32, seq uint16, ts uint32) {
	binary.BigEndian.PutUint32(dst[0:4], ssrc)
	binary.BigEndian.PutUint16(dst[4:6], seq)
	dst[6] = 0
	dst[7] = 0
	binary.BigEndian.PutUint32(dst[8:12], ts)
}

func obfsBuildNonce(ssrc uint32, seq uint16, ts uint32) []byte {
	n := make([]byte, 12)
	var tmp [12]byte
	obfsBuildNonceInto(&tmp, ssrc, seq, ts)
	copy(n, tmp[:])
	return n
}

func obfsWrapWireLen(payloadLen int, cfg *ObfsConfig) int {
	pad := cfg.PaddingMax
	if pad < 0 {
		pad = 0
	}
	return 12 + payloadLen + chacha20poly1305.Overhead + pad
}

func obfsWrapPacketInto(dst []byte, aead cipher.AEAD, payload []byte, cfg *ObfsConfig, state *ObfsState) (int, error) {
	if len(payload) == 0 {
		return 0, errors.New("obfs: empty payload")
	}

	var randomBytes [5]byte
	if _, err := rand.Read(randomBytes[:]); err != nil {
		return 0, fmt.Errorf("obfs: random RTP metadata: %w", err)
	}
	seq, ts := state.nextHeader(time.Now(), randomBytes[2], randomBytes[4])

	padTotal := 0
	padRand := 0
	if cfg.PaddingMax > 0 && useRTPPadding(randomBytes[0]) {
		padRand = int(randomBytes[1]) % cfg.PaddingMax
		padTotal = padRand + 1
	}
	outLen := 12 + len(payload) + chacha20poly1305.Overhead + padTotal
	if outLen > len(dst) {
		return 0, fmt.Errorf("obfs: dst too small (%d > %d)", outLen, len(dst))
	}

	dst[0] = 0x80
	if padTotal > 0 {
		dst[0] |= 0x20
	}
	dst[1] = cfg.PayloadType & 0x7F
	if useRTPMarker(randomBytes[3]) {
		dst[1] |= 0x80
	}
	binary.BigEndian.PutUint16(dst[2:4], seq)
	binary.BigEndian.PutUint32(dst[4:8], ts)
	binary.BigEndian.PutUint32(dst[8:12], cfg.SSRC)

	var nonce [12]byte
	obfsBuildNonceInto(&nonce, cfg.SSRC, seq, ts)
	sealed := aead.Seal(dst[12:12], nonce[:], payload, dst[:12])
	padStart := 12 + len(sealed)

	if padRand > 0 {
		if _, err := rand.Read(dst[padStart : padStart+padRand]); err != nil {
			return 0, fmt.Errorf("obfs: random padding bytes: %w", err)
		}
	}
	if padTotal > 0 {
		dst[outLen-1] = byte(padTotal)
	}
	return outLen, nil
}

func obfsWrapPacket(key, payload []byte, cfg *ObfsConfig, state *ObfsState) ([]byte, error) {
	if len(key) != wrapKeyLen {
		return nil, fmt.Errorf("obfs: key must be %d bytes (got %d)", wrapKeyLen, len(key))
	}
	aead, err := getAEAD(key)
	if err != nil {
		return nil, fmt.Errorf("obfs: cipher init: %w", err)
	}
	out := make([]byte, obfsWrapWireLen(len(payload), cfg))
	n, err := obfsWrapPacketInto(out, aead, payload, cfg, state)
	if err != nil {
		return nil, err
	}
	return out[:n], nil
}

func obfsUnwrapPacketAEAD(aead cipher.AEAD, wire, dst []byte) (int, error) {
	if len(wire) < 13 {
		return 0, errors.New("obfs: packet too short")
	}
	if (wire[0] >> 6) != 2 {
		return 0, errors.New("obfs: not RTP v2")
	}
	seq := binary.BigEndian.Uint16(wire[2:4])
	ts := binary.BigEndian.Uint32(wire[4:8])
	ssrc := binary.BigEndian.Uint32(wire[8:12])

	payloadEnd := len(wire)
	if wire[0]&0x20 != 0 {
		padLen := int(wire[len(wire)-1])
		if padLen == 0 || padLen > payloadEnd-12 {
			return 0, fmt.Errorf("obfs: invalid padding length %d", padLen)
		}
		payloadEnd -= padLen
	}
	ciphertextLen := payloadEnd - 12
	if ciphertextLen <= chacha20poly1305.Overhead {
		return 0, errors.New("obfs: no payload")
	}
	if ciphertextLen-chacha20poly1305.Overhead > len(dst) {
		return 0, errors.New("obfs: dst buffer too small")
	}
	var nonce [12]byte
	obfsBuildNonceInto(&nonce, ssrc, seq, ts)
	plain, err := aead.Open(dst[:0], nonce[:], wire[12:payloadEnd], wire[:12])
	if err != nil {
		return 0, fmt.Errorf("obfs: auth: %w", err)
	}
	return len(plain), nil
}

func obfsUnwrapPacket(key, wire, dst []byte) (int, error) {
	if len(key) != wrapKeyLen {
		return 0, fmt.Errorf("obfs: key must be %d bytes (got %d)", wrapKeyLen, len(key))
	}
	aead, err := getAEAD(key)
	if err != nil {
		return 0, fmt.Errorf("obfs: cipher init: %w", err)
	}
	return obfsUnwrapPacketAEAD(aead, wire, dst)
}

func obfsIsRTPPacket(wire []byte) bool {
	if len(wire) < 13 {
		return false
	}
	if (wire[0] >> 6) != 2 {
		return false
	}
	pt := wire[1] & 0x7F
	return pt == 111 || pt == 96
}

func readUint24(value []byte) int {
	return int(value[0])<<16 | int(value[1])<<8 | int(value[2])
}

func isDTLSClientHello(packet []byte) bool {
	const (
		dtlsRecordHeader    = 13
		dtlsHandshakeHeader = 12
		clientHelloType     = 1
		minClientHelloBody  = 38
	)
	if len(packet) < dtlsRecordHeader+dtlsHandshakeHeader || packet[0] != 22 || packet[1] != 0xfe || (packet[2] != 0xfd && packet[2] != 0xff) {
		return false
	}
	recordLength := int(binary.BigEndian.Uint16(packet[11:13]))
	if recordLength < dtlsHandshakeHeader || dtlsRecordHeader+recordLength > len(packet) || packet[13] != clientHelloType {
		return false
	}
	handshakeLength := readUint24(packet[14:17])
	fragmentOffset := readUint24(packet[19:22])
	fragmentLength := readUint24(packet[22:25])
	return handshakeLength >= minClientHelloBody && fragmentOffset == 0 && fragmentLength > 0 &&
		fragmentLength <= handshakeLength && dtlsHandshakeHeader+fragmentLength <= recordLength
}

type wrapReplayCache struct {
	mu      sync.Mutex
	entries map[[sha256.Size]byte]time.Time
}

func newWrapReplayCache() *wrapReplayCache {
	return &wrapReplayCache{entries: make(map[[sha256.Size]byte]time.Time)}
}

func (c *wrapReplayCache) Admit(packet []byte, now time.Time) bool {
	digest := sha256.Sum256(packet)
	c.mu.Lock()
	defer c.mu.Unlock()
	if expiresAt, exists := c.entries[digest]; exists && now.Before(expiresAt) {
		return false
	}
	var oldestDigest [sha256.Size]byte
	var oldestTime time.Time
	for candidate, expiresAt := range c.entries {
		if !now.Before(expiresAt) {
			delete(c.entries, candidate)
			continue
		}
		if oldestTime.IsZero() || expiresAt.Before(oldestTime) {
			oldestDigest = candidate
			oldestTime = expiresAt
		}
	}
	if len(c.entries) >= wrapReplayCacheSize {
		delete(c.entries, oldestDigest)
	}
	c.entries[digest] = now.Add(wrapReplayTTL)
	return true
}

func acceptWrappedPacket(keys *wrapKeyStore, raw []byte) bool {
	if keys == nil || len(raw) == 0 || len(raw) > maxWrappedPacketSize || !obfsIsRTPPacket(raw) {
		return false
	}

	var plaintext [maxWrappedPacketSize]byte
	key, _, n, err := keys.Unwrap(raw, plaintext[:])
	if len(key) > 0 {
		zeroBytes(key)
	}
	valid := err == nil && isDTLSClientHello(plaintext[:n])
	if n > 0 {
		zeroBytes(plaintext[:n])
	}
	return valid
}

func acceptWrappedPacketOnce(keys *wrapKeyStore, replayCache *wrapReplayCache, raw []byte) bool {
	return acceptWrappedPacket(keys, raw) && replayCache.Admit(raw, time.Now())
}

func listenWrapped(addr *net.UDPAddr, keys *wrapKeyStore) (*wrapPacketListener, error) {
	if keys == nil || keys.Count() == 0 {
		return nil, errors.New("wrap: no active keys")
	}
	replayCache := newWrapReplayCache()
	inner, err := (&pionudp.ListenConfig{
		// Pion otherwise allocates a virtual connection for every datagram,
		// including unauthenticated noise. Validate the first WRAP packet before
		// it can consume a DTLS worker and a global connection slot.
		AcceptFilter: func(packet []byte) bool {
			return acceptWrappedPacketOnce(keys, replayCache, packet)
		},
		Backlog:         wrappedListenBacklog,
		ReadBufferSize:  wrappedSocketBuffer,
		WriteBufferSize: wrappedSocketBuffer,
	}).Listen("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("wrap: udp listen: %w", err)
	}
	return &wrapPacketListener{
		inner: dtlsnet.PacketListenerFromListener(inner),
		keys:  keys,
	}, nil
}

type wrapPacketListener struct {
	inner dtlsnet.PacketListener
	keys  *wrapKeyStore

	connsMu sync.RWMutex
	conns   map[string]*wrapPacketConn
}

func (l *wrapPacketListener) Accept() (net.PacketConn, net.Addr, error) {
	pc, addr, err := l.inner.Accept()
	if err != nil {
		return pc, addr, err
	}
	wrapped := &wrapPacketConn{inner: pc, keys: l.keys}
	addrKey := addr.String()
	wrapped.onClose = func() {
		l.connsMu.Lock()
		if l.conns[addrKey] == wrapped {
			delete(l.conns, addrKey)
		}
		l.connsMu.Unlock()
	}
	l.connsMu.Lock()
	if l.conns == nil {
		l.conns = make(map[string]*wrapPacketConn)
	}
	l.conns[addrKey] = wrapped
	l.connsMu.Unlock()
	return wrapped, addr, nil
}

func (l *wrapPacketListener) Close() error   { return l.inner.Close() }
func (l *wrapPacketListener) Addr() net.Addr { return l.inner.Addr() }

func (l *wrapPacketListener) IdentityFor(addr net.Addr) (wrapIdentity, bool) {
	if addr == nil {
		return wrapIdentity{}, false
	}
	l.connsMu.RLock()
	conn := l.conns[addr.String()]
	l.connsMu.RUnlock()
	if conn == nil {
		return wrapIdentity{}, false
	}
	return conn.Identity()
}

type wrapPacketConn struct {
	inner     net.PacketConn
	keys      *wrapKeyStore
	key       []byte
	aead      cipher.AEAD
	identity  wrapIdentity
	selected  int32
	authLog   int32
	obfsCfg   *ObfsConfig
	obfsWrite *ObfsState

	rxMu  sync.Mutex
	txMu  sync.Mutex
	txBuf []byte

	closeOnce sync.Once
	onClose   func()
}

func (c *wrapPacketConn) Identity() (wrapIdentity, bool) {
	if atomic.LoadInt32(&c.selected) != 1 {
		return wrapIdentity{}, false
	}
	return c.identity, c.identity.Password != ""
}

func (c *wrapPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	var buf [maxWrappedPacketSize]byte

	// Повреждённый пакет не должен закрывать целую DTLS-сессию. Это особенно
	// важно после аутентификации: UDP позволяет подмешать пакет в существующий
	// 4-tuple, а Pion передаёт ошибку ReadFrom вверх как ошибку транспорта.
	for {
		n, addr, err := c.inner.ReadFrom(buf[:])
		if err != nil {
			return 0, addr, err
		}
		if n == 0 || buf[0] == 0x00 || buf[0] == 0x16 {
			continue
		}

		raw := buf[:n]

		// Быстрый путь (Fast path) без захвата мьютекса для последующих пакетов.
		if atomic.LoadInt32(&c.selected) == 1 {
			m, uErr := obfsUnwrapPacketAEAD(c.aead, raw, p)
			if uErr != nil {
				continue
			}
			return m, addr, nil
		}

		// Медленный путь (Slow path) с мьютексом только для выбора первого ключа.
		c.rxMu.Lock()
		if atomic.LoadInt32(&c.selected) == 1 {
			m, uErr := obfsUnwrapPacketAEAD(c.aead, raw, p)
			c.rxMu.Unlock()
			if uErr != nil {
				continue
			}
			return m, addr, nil
		}

		key, identity, m, uErr := c.keys.Unwrap(raw, p)
		if uErr != nil {
			c.rxMu.Unlock()
			if atomic.CompareAndSwapInt32(&c.authLog, 0, 1) {
				log.Printf("[WRAP] Отказ: RTP AEAD auth failed from %s (keys=%d)", addr.String(), c.keys.Count())
			}
			continue
		}
		aead, aErr := getAEAD(key)
		if aErr != nil {
			c.rxMu.Unlock()
			return 0, addr, fmt.Errorf("wrap: cipher init: %w", aErr)
		}
		c.key = key
		c.aead = aead
		c.identity = identity
		c.obfsCfg = NewObfsConfig()

		if len(raw) > 1 {
			c.obfsCfg.PayloadType = raw[1] & 0x7F
			if c.obfsCfg.PayloadType == 96 {
				c.obfsCfg.PaddingMax = 60
			}
		}
		c.obfsWrite = NewObfsState()
		atomic.StoreInt32(&c.selected, 1)
		c.rxMu.Unlock()
		if atomic.CompareAndSwapInt32(&c.authLog, 0, 1) {
			log.Printf("[WRAP] OK: ключ выбран для %s (keys=%d), PT=%d", addr.String(), c.keys.Count(), c.obfsCfg.PayloadType)
		}
		return m, addr, nil
	}
}

func (c *wrapPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if atomic.LoadInt32(&c.selected) == 0 || c.aead == nil {
		return 0, errors.New("wrap: key not selected")
	}
	c.txMu.Lock()
	defer c.txMu.Unlock()

	need := obfsWrapWireLen(len(p), c.obfsCfg)
	if cap(c.txBuf) < need {
		c.txBuf = make([]byte, need)
	}
	n, wErr := obfsWrapPacketInto(c.txBuf[:need], c.aead, p, c.obfsCfg, c.obfsWrite)
	if wErr != nil {
		return 0, fmt.Errorf("obfs wrap: %w", wErr)
	}
	if _, err := c.inner.WriteTo(c.txBuf[:n], addr); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *wrapPacketConn) Close() error {
	c.closeOnce.Do(func() {
		if c.onClose != nil {
			c.onClose()
		}
	})
	return c.inner.Close()
}
func (c *wrapPacketConn) LocalAddr() net.Addr                { return c.inner.LocalAddr() }
func (c *wrapPacketConn) SetDeadline(t time.Time) error      { return c.inner.SetDeadline(t) }
func (c *wrapPacketConn) SetReadDeadline(t time.Time) error  { return c.inner.SetReadDeadline(t) }
func (c *wrapPacketConn) SetWriteDeadline(t time.Time) error { return c.inner.SetWriteDeadline(t) }
