package main

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestServerConfigurationValidation(t *testing.T) {
	for _, listen := range []string{"", "0.0.0.0:0", "0.0.0.0:65536", "[::]:56000", "not-an-address"} {
		if _, err := resolveServerListenAddress(listen); err == nil {
			t.Fatalf("resolveServerListenAddress(%q) succeeded", listen)
		}
	}
	if address, err := resolveServerListenAddress("0.0.0.0:56000"); err != nil || address.Port != 56000 {
		t.Fatalf("valid listen address = %v, %v", address, err)
	}

	for _, servers := range []string{"", "1.1.1.1,", "not-an-ip", "1.1.1.1,not-an-ip", "2606:4700:4700::1111", "1.1.1.1,2001:4860:4860::8888"} {
		if err := validateDNSServers(servers); err == nil {
			t.Fatalf("validateDNSServers(%q) succeeded", servers)
		}
	}
	if err := validateDNSServers("1.1.1.1,8.8.8.8"); err != nil {
		t.Fatalf("valid DNS list: %v", err)
	}

	for _, credentials := range [][2]string{
		{"42", ""},
		{"", "123:token"},
		{"-42", "123:token"},
		{"42", "invalid"},
		{"42", "0:token"},
		{"42", "123:token with space"},
	} {
		if err := validateTelegramCredentials(credentials[0], credentials[1]); err == nil {
			t.Fatalf("validateTelegramCredentials(%q, %q) succeeded", credentials[0], credentials[1])
		}
	}
	if err := validateTelegramCredentials("42", "123:valid-token_1"); err != nil {
		t.Fatalf("valid Telegram credentials: %v", err)
	}
}

func TestGetPublicIPRejectsUntrustedResponsesAndCachesValidIPv4(t *testing.T) {
	responses := []string{"10.0.0.1", "not-an-ip", "198.51.100.42"}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		index := int(requests.Add(1) - 1)
		if index >= len(responses) {
			index = len(responses) - 1
		}
		_, _ = w.Write([]byte(responses[index]))
	}))
	defer server.Close()

	oldURL := publicIPServiceURL
	oldClient := publicIPHTTPClient
	publicIPServiceURL = server.URL
	publicIPHTTPClient = server.Client()
	publicIPCache.Lock()
	oldCached := publicIPCache.value
	publicIPCache.value = ""
	publicIPCache.Unlock()
	t.Cleanup(func() {
		publicIPServiceURL = oldURL
		publicIPHTTPClient = oldClient
		publicIPCache.Lock()
		publicIPCache.value = oldCached
		publicIPCache.Unlock()
	})

	if got := getPublicIP(); got != "YOUR_SERVER_IP" {
		t.Fatalf("private response = %q", got)
	}
	if got := getPublicIP(); got != "YOUR_SERVER_IP" {
		t.Fatalf("invalid response = %q", got)
	}
	if got := getPublicIP(); got != "198.51.100.42" {
		t.Fatalf("valid public response = %q", got)
	}
	if got := getPublicIP(); got != "198.51.100.42" {
		t.Fatalf("cached public response = %q", got)
	}
	if got := requests.Load(); got != 3 {
		t.Fatalf("HTTP requests = %d, want 3", got)
	}
}
