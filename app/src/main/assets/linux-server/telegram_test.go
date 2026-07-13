package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func withTelegramTestServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(handler)
	oldBaseURL := telegramAPIBaseURL
	oldClient := telegramHTTPClient
	telegramAPIBaseURL = server.URL
	telegramHTTPClient = server.Client()
	t.Cleanup(func() {
		telegramAPIBaseURL = oldBaseURL
		telegramHTTPClient = oldClient
		server.Close()
	})
	return server
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
