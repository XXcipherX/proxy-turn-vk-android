package main

import (
	"strings"
	"testing"

	fhttp "github.com/bogdanfinn/fhttp"
)

func TestCaptchaDomainFromRedirectURI(t *testing.T) {
	tests := []struct {
		name        string
		redirectURI string
		want        string
	}{
		{name: "vk com", redirectURI: "https://id.vk.ru/not_robot_captcha?domain=vk.com&session_token=token", want: "vk.com"},
		{name: "vk ru", redirectURI: "https://id.vk.ru/not_robot_captcha?domain=vk.ru&session_token=token", want: "vk.ru"},
		{name: "missing", redirectURI: "https://id.vk.ru/not_robot_captcha?session_token=token", want: "vk.com"},
		{name: "malformed", redirectURI: "%", want: "vk.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := captchaDomainFromRedirectURI(tt.redirectURI); got != tt.want {
				t.Fatalf("captchaDomainFromRedirectURI() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVKMigrationConstants(t *testing.T) {
	if vkWebHost != "vk.ru" {
		t.Fatalf("vkWebHost = %q, want vk.ru", vkWebHost)
	}
	if vkCallJoinBase != "https://vk.ru/call/join/" {
		t.Fatalf("vkCallJoinBase = %q", vkCallJoinBase)
	}
}

func TestChrome146BrowserHeadersAreConsistent(t *testing.T) {
	req, err := fhttp.NewRequest("GET", "https://vk.ru", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	applyBrowserProfileFhttp(req, chrome146Profile)

	if got := req.Header.Get("User-Agent"); got != chrome146Profile.UserAgent {
		t.Fatalf("User-Agent = %q, want %q", got, chrome146Profile.UserAgent)
	}
	if !strings.Contains(req.Header.Get("User-Agent"), "Chrome/146.") {
		t.Fatalf("User-Agent does not identify Chrome 146: %q", req.Header.Get("User-Agent"))
	}
	if !strings.Contains(req.Header.Get("sec-ch-ua"), `v="146"`) {
		t.Fatalf("sec-ch-ua does not identify version 146: %q", req.Header.Get("sec-ch-ua"))
	}
}
