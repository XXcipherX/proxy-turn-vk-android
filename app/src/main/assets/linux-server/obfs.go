package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"crypto/cipher"

	"golang.org/x/crypto/chacha20poly1305"

	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	pionudp "github.com/pion/transport/v4/udp"
)

const (
	wrapNonceLen = 12
	wrapKeyLen   = 32
)

var aeadCache sync.Map

// Локальный пул буферов для чтения, чтобы не аллоцировать память на каждый пакет
var obfsBufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 2048)
		return &b
	},
}

func getAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != wrapKeyLen {
		return nil, fmt.Errorf("obfs: key must be %d bytes", wrapKeyLen)
	}
	keyStr := string(key)
	if val, ok := aeadCache.Load(keyStr); ok {
		return val.(cipher.AEAD), nil
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	aeadCache.Store(keyStr, aead)
	return aead, nil
}

type ObfsConfig struct {
	SSRC        uint32
	PayloadType uint8
	PaddingMax  int
}

type ObfsState struct {
	initSeq uint16
	initTs  uint32
	count   uint64 // Поле обновляется атомарно через sync/atomic
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
		initSeq: binary.BigEndian.Uint16(buf[0:2]),
		initTs:  binary.BigEndian.Uint32(buf[2:6]),
		count:   0,
	}
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
	if pad < 1 {
		pad = 1
	}
	return 12 + payloadLen + chacha20poly1305.Overhead + pad
}

func obfsMix64(v uint64) uint64 {
	x := (v + 0x9e3779b97f4a7c15) ^ 0xbf58476d1ce4e5b9
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return x
}

func obfsWrapPacketInto(dst []byte, aead cipher.AEAD, payload []byte, cfg *ObfsConfig, state *ObfsState) (int, error) {
	if len(payload) == 0 {
		return 0, errors.New("obfs: empty payload")
	}

	c := atomic.AddUint64(&state.count, 1) - 1
	seq := state.initSeq + uint16(c)
	ts := state.initTs + uint32(c)*960 + uint32(c>>16)

	padRand := 0
	x := uint64(0)
	if cfg.PaddingMax > 0 {
		x = obfsMix64(c)
		padRand = int(x % uint64(cfg.PaddingMax))
	}
	padTotal := padRand + 1
	outLen := 12 + len(payload) + chacha20poly1305.Overhead + padTotal
	if outLen > len(dst) {
		return 0, fmt.Errorf("obfs: dst too small (%d > %d)", outLen, len(dst))
	}

	dst[0] = 0x80 | 0x20
	dst[1] = cfg.PayloadType & 0x7F
	binary.BigEndian.PutUint16(dst[2:4], seq)
	binary.BigEndian.PutUint32(dst[4:8], ts)
	binary.BigEndian.PutUint32(dst[8:12], cfg.SSRC)

	var nonce [12]byte
	obfsBuildNonceInto(&nonce, cfg.SSRC, seq, ts)
	sealed := aead.Seal(dst[12:12], nonce[:], payload, dst[:12])
	padStart := 12 + len(sealed)

	if padRand > 0 {
		for i := 0; i < padRand; i++ {
			dst[padStart+i] = byte(x >> ((i % 8) * 8))
		}
	}
	dst[outLen-1] = byte(padTotal)
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

func listenWrapped(addr *net.UDPAddr, keys *wrapKeyStore) (dtlsnet.PacketListener, error) {
	if keys == nil || keys.Count() == 0 {
		return nil, errors.New("wrap: no active keys")
	}
	inner, err := pionudp.Listen("udp", addr)
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
}

func (l *wrapPacketListener) Accept() (net.PacketConn, net.Addr, error) {
	pc, addr, err := l.inner.Accept()
	if err != nil {
		return pc, addr, err
	}
	return &wrapPacketConn{inner: pc, keys: l.keys}, addr, nil
}

func (l *wrapPacketListener) Close() error   { return l.inner.Close() }
func (l *wrapPacketListener) Addr() net.Addr { return l.inner.Addr() }

type wrapPacketConn struct {
	inner     net.PacketConn
	keys      *wrapKeyStore
	key       []byte
	aead      cipher.AEAD
	selected  int32
	authLog   int32
	obfsCfg   *ObfsConfig
	obfsWrite *ObfsState

	rxMu  sync.Mutex
	txMu  sync.Mutex
	txBuf []byte
}

func (c *wrapPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	// Получаем буфер из пула во временное пользование (вне мьютекса!)
	bufPtr := obfsBufPool.Get().(*[]byte)
	defer obfsBufPool.Put(bufPtr)
	buf := *bufPtr

	var n int
	var addr net.Addr
	var err error

	// Сетевое чтение происходит без блокировки rxMu
	for {
		n, addr, err = c.inner.ReadFrom(buf)
		if err != nil {
			return 0, addr, err
		}
		if n > 0 && (buf[0] == 0x00 || buf[0] == 0x16) {
			continue
		}
		break
	}

	raw := buf[:n]

	// Блокируем только на короткие вычисления
	c.rxMu.Lock()
	defer c.rxMu.Unlock()

	if atomic.LoadInt32(&c.selected) == 0 {
		key, m, uErr := c.keys.Unwrap(raw, p)
		if uErr != nil {
			if atomic.CompareAndSwapInt32(&c.authLog, 0, 1) {
				log.Printf("[WRAP] Отказ: RTP AEAD auth failed from %s (keys=%d)", addr.String(), c.keys.Count())
			}
			return 0, addr, uErr
		}
		aead, aErr := getAEAD(key)
		if aErr != nil {
			return 0, addr, fmt.Errorf("wrap: cipher init: %w", aErr)
		}
		c.key = key
		c.aead = aead
		c.obfsCfg = NewObfsConfig()

		if len(raw) > 1 {
			c.obfsCfg.PayloadType = raw[1] & 0x7F
		}
		c.obfsWrite = NewObfsState()
		atomic.StoreInt32(&c.selected, 1)
		if atomic.CompareAndSwapInt32(&c.authLog, 0, 1) {
			log.Printf("[WRAP] OK: ключ выбран для %s (keys=%d), PT=%d", addr.String(), c.keys.Count(), c.obfsCfg.PayloadType)
		}
		return m, addr, nil
	}

	m, uErr := obfsUnwrapPacketAEAD(c.aead, raw, p)
	if uErr != nil {
		return 0, addr, fmt.Errorf("obfs unwrap: %w", uErr)
	}
	return m, addr, nil
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

func (c *wrapPacketConn) Close() error                       { return c.inner.Close() }
func (c *wrapPacketConn) LocalAddr() net.Addr                { return c.inner.LocalAddr() }
func (c *wrapPacketConn) SetDeadline(t time.Time) error      { return c.inner.SetDeadline(t) }
func (c *wrapPacketConn) SetReadDeadline(t time.Time) error  { return c.inner.SetReadDeadline(t) }
func (c *wrapPacketConn) SetWriteDeadline(t time.Time) error { return c.inner.SetWriteDeadline(t) }
