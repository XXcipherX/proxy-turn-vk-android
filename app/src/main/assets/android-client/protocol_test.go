package main

import (
	"net"
	"strings"
	"testing"
)

func TestRequestConfigSendsLifecycleIdentity(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	request := make(chan string, 1)
	serverErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 512)
		n, err := server.Read(buf)
		if err != nil {
			serverErr <- err
			return
		}
		request <- string(buf[:n])
		_, err = server.Write([]byte("wg-config"))
		serverErr <- err
	}()

	config, err := RequestConfig(
		client,
		"9000",
		"android-device",
		"Strong-Test_7kM9xQ2",
		"550e8400-e29b-41d4-a716-446655440000",
		"27",
	)
	if err != nil {
		t.Fatalf("RequestConfig: %v", err)
	}
	if config != "wg-config" {
		t.Fatalf("config = %q, want %q", config, "wg-config")
	}
	if got := <-request; got != "GETCONF:9000|android-device|Strong-Test_7kM9xQ2|550e8400-e29b-41d4-a716-446655440000|27" {
		t.Fatalf("request = %q", got)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server: %v", err)
	}
}

func TestRequestConfigReportsRetiredGeneration(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		buf := make([]byte, 512)
		_, _ = server.Read(buf)
		_, _ = server.Write([]byte("DENIED:stale_generation"))
	}()

	_, err := RequestConfig(client, "9000", "device", "password", "generation", "worker")
	if err == nil || !strings.Contains(err.Error(), "FATAL_LIFECYCLE") {
		t.Fatalf("error = %v, want FATAL_LIFECYCLE", err)
	}
}
