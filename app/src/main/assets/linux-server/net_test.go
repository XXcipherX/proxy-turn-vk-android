package main

import "testing"

func TestDefaultInterfaceFromRoutes(t *testing.T) {
	routes := "default via 192.0.2.1 dev ens3 proto dhcp src 192.0.2.10\n192.0.2.0/24 dev ens3"
	if got := defaultInterfaceFromRoutes(routes); got != "ens3" {
		t.Fatalf("defaultInterfaceFromRoutes() = %q, want ens3", got)
	}
	if got := defaultInterfaceFromRoutes("10.0.0.0/8 dev eth0"); got != "" {
		t.Fatalf("route without default returned %q", got)
	}
}
