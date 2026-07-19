package main

import "testing"

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
