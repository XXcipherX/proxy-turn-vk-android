package main

import (
	"log"
	"net"
	"syscall"
)

// vkDiagnosticDialer records the destination and address family selected by
// tls-client. This makes Android failures such as EADDRNOTAVAIL diagnosable
// without changing address selection or binding the connection manually.
func vkDiagnosticDialer() net.Dialer {
	return net.Dialer{
		Control: func(network, address string, _ syscall.RawConn) error {
			log.Printf("[VK Network] dial request: network=%s address=%s", network, address)
			return nil
		},
	}
}
