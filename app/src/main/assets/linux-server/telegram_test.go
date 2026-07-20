package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func withTelegramTestServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(handler)
	oldBaseURL := telegramAPIBaseURL
	oldClient := telegramHTTPClient
	oldPollingClient := telegramPollingHTTPClient
	telegramAPIBaseURL = server.URL
	telegramHTTPClient = server.Client()
	telegramPollingHTTPClient = server.Client()
	t.Cleanup(func() {
		telegramAPIBaseURL = oldBaseURL
		telegramHTTPClient = oldClient
		telegramPollingHTTPClient = oldPollingClient
		server.Close()
	})
	return server
}

func TestGetTelegramUpdatesHandlesRateLimitAndRedactsToken(t *testing.T) {
	const token = "ci-polling-secret"
	withTelegramTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.RawQuery, "timeout=60") || !strings.Contains(r.URL.RawQuery, "offset=42") {
			t.Errorf("unexpected query: %q", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"ok":false,"description":"retry ci-polling-secret","parameters":{"retry_after":3}}`))
	})

	updates, retryAfter, err := getTelegramUpdates(context.Background(), telegramPollingHTTPClient, token, 42)
	if err == nil {
		t.Fatal("getTelegramUpdates accepted a rate-limited response")
	}
	if updates != nil {
		t.Fatalf("updates = %v, want nil", updates)
	}
	if retryAfter != 3*time.Second {
		t.Fatalf("retryAfter = %s, want 3s", retryAfter)
	}
	if strings.Contains(err.Error(), token) || !strings.Contains(err.Error(), "<redacted>") {
		t.Fatalf("token was not redacted: %v", err)
	}
}

func TestGetTelegramUpdatesRejectsInvalidSuccessPayload(t *testing.T) {
	withTelegramTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":false,"description":"conflict"}`))
	})
	if _, _, err := getTelegramUpdates(context.Background(), telegramPollingHTTPClient, "token", 0); err == nil {
		t.Fatal("getTelegramUpdates accepted ok=false")
	}
}

func TestTelegramPollingBackoffIsBounded(t *testing.T) {
	oldMin := telegramPollingMinBackoff
	oldMax := telegramPollingMaxBackoff
	telegramPollingMinBackoff = 10 * time.Millisecond
	telegramPollingMaxBackoff = 80 * time.Millisecond
	t.Cleanup(func() {
		telegramPollingMinBackoff = oldMin
		telegramPollingMaxBackoff = oldMax
	})

	want := []time.Duration{10, 20, 40, 80, 80}
	for index, milliseconds := range want {
		if got := telegramPollingBackoff(index + 1); got != milliseconds*time.Millisecond {
			t.Fatalf("failure %d backoff = %s, want %s", index+1, got, milliseconds*time.Millisecond)
		}
	}
}

func TestTelegramDialogStateDoesNotMixMainAndTemporaryFlows(t *testing.T) {
	var dialog telegramDialogState
	dialog.beginMainPasswordLink()
	dialog.beginTemporaryPassword()

	if dialog.stage != telegramDialogWaitingForDays || dialog.target != telegramDialogTemporaryPassword {
		t.Fatalf("temporary flow did not replace main-link state: %+v", dialog)
	}
	if dialog.useDefaultPorts() {
		t.Fatal("stale port callback advanced a flow that was waiting for days")
	}
	if !dialog.acceptDays(30) || !dialog.useDefaultPorts() {
		t.Fatal("valid temporary-password flow did not advance")
	}
	target, days, ports, ok := dialog.finishHash()
	if !ok || target != telegramDialogTemporaryPassword || days != 30 || ports != "56000,56001,9000" {
		t.Fatalf("completed temporary flow = (%v, %d, %q, %v)", target, days, ports, ok)
	}
	if dialog.stage != telegramDialogIdle || dialog.target != telegramDialogNoTarget {
		t.Fatalf("completed flow retained stale state: %+v", dialog)
	}
}

func TestTelegramDialogRejectsStalePortCallbacks(t *testing.T) {
	var dialog telegramDialogState
	if dialog.useDefaultPorts() || dialog.requestCustomPorts() {
		t.Fatal("idle dialog accepted a stale port callback")
	}

	dialog.beginMainPasswordLink()
	if !dialog.requestCustomPorts() || !dialog.acceptPorts("56002,56003,9001") {
		t.Fatal("main-link custom-port flow did not advance")
	}
	dialog.reset()
	if _, _, _, ok := dialog.finishHash(); ok {
		t.Fatal("reset dialog completed a stale hash flow")
	}
}

func TestPostTelegramSuccess(t *testing.T) {
	const token = "ci-secret-token"
	withTelegramTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/bot"+token+"/sendMessage" {
			t.Errorf("request path = %q", r.URL.Path)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type = %q", r.Header.Get("Content-Type"))
		}
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode payload: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	if err := postTelegram(token, "sendMessage", map[string]interface{}{"chat_id": 42, "text": "hello"}); err != nil {
		t.Fatalf("postTelegram: %v", err)
	}
}

func TestPostTelegramRejectsErrorsAndRedactsToken(t *testing.T) {
	const token = "ci-secret-token"
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{name: "HTTP failure", status: http.StatusInternalServerError, body: `upstream echoed ci-secret-token`},
		{name: "API failure", status: http.StatusOK, body: `{"ok":false,"description":"invalid ci-secret-token"}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			withTelegramTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			})
			err := postTelegram(token, "sendMessage", map[string]interface{}{"text": "hello"})
			if err == nil {
				t.Fatal("postTelegram accepted a failed API response")
			}
			if strings.Contains(err.Error(), token) {
				t.Fatalf("error exposed Telegram token: %v", err)
			}
			if !strings.Contains(err.Error(), "<redacted>") {
				t.Fatalf("error did not mark redacted content: %v", err)
			}
		})
	}
}
