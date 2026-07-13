package main

import (
	"net"
	"net/netip"
	"sync"

	wgconn "golang.zx2c4.com/wireguard/conn"
)

// loopbackBind keeps the userspace WireGuard transport private to the server.
// Only the local DTLS proxy needs to exchange packets with this socket.
type loopbackBind struct {
	mu   sync.Mutex
	conn *net.UDPConn
}

var _ wgconn.Bind = (*loopbackBind)(nil)

func newLoopbackBind() *loopbackBind {
	return &loopbackBind{}
}

func (b *loopbackBind) Open(port uint16) ([]wgconn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conn != nil {
		return nil, 0, wgconn.ErrBindAlreadyOpen
	}

	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: int(port),
	})
	if err != nil {
		return nil, 0, err
	}
	_ = udpConn.SetReadBuffer(2 * 1024 * 1024)
	_ = udpConn.SetWriteBuffer(2 * 1024 * 1024)
	b.conn = udpConn

	actualPort := udpConn.LocalAddr().(*net.UDPAddr).Port
	return []wgconn.ReceiveFunc{b.receive}, uint16(actualPort), nil
}

func (b *loopbackBind) receive(packets [][]byte, sizes []int, endpoints []wgconn.Endpoint) (int, error) {
	b.mu.Lock()
	udpConn := b.conn
	b.mu.Unlock()
	if udpConn == nil {
		return 0, net.ErrClosed
	}
	if len(packets) == 0 || len(sizes) == 0 || len(endpoints) == 0 {
		return 0, nil
	}

	n, addr, err := udpConn.ReadFromUDPAddrPort(packets[0])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	endpoints[0] = &wgconn.StdNetEndpoint{AddrPort: addr}
	return 1, nil
}

func (b *loopbackBind) Close() error {
	b.mu.Lock()
	udpConn := b.conn
	b.conn = nil
	b.mu.Unlock()
	if udpConn == nil {
		return nil
	}
	return udpConn.Close()
}

func (b *loopbackBind) SetMark(uint32) error {
	return nil
}

func (b *loopbackBind) Send(packets [][]byte, endpoint wgconn.Endpoint) error {
	stdEndpoint, ok := endpoint.(*wgconn.StdNetEndpoint)
	if !ok {
		return wgconn.ErrWrongEndpointType
	}
	b.mu.Lock()
	udpConn := b.conn
	b.mu.Unlock()
	if udpConn == nil {
		return net.ErrClosed
	}

	for _, packet := range packets {
		if _, err := udpConn.WriteToUDPAddrPort(packet, stdEndpoint.AddrPort); err != nil {
			return err
		}
	}
	return nil
}

func (b *loopbackBind) ParseEndpoint(value string) (wgconn.Endpoint, error) {
	addr, err := netip.ParseAddrPort(value)
	if err != nil {
		return nil, err
	}
	return &wgconn.StdNetEndpoint{AddrPort: addr}, nil
}

func (b *loopbackBind) BatchSize() int {
	return 1
}
