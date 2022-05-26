package tsc

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestMakeJsonRequest(t *testing.T) {
	apiKey := "fake_key"
	endpoint := wrapEndpoint

	handler := http.HandlerFunc(func(writer http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/1/document/wrap" {
			t.Errorf("request path %q", r.URL.Path)
		}
		authHeaders := r.Header["Authorization"]
		if len(authHeaders) != 1 {
			t.Fatalf("%d auth headers: %v", len(authHeaders), authHeaders)
		}
		authHeader := authHeaders[0]
		if authHeader != "cmk "+apiKey {
			t.Errorf("auth header %q", authHeader)
		}

		fmt.Fprintf(writer, "{}")
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	url, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	r := newTenantSecurityRequest(apiKey, url)
	reqBody := io.NopCloser(strings.NewReader(`{}`))
	respBody, err := r.doRequest(endpoint, reqBody)
	if err != nil {
		t.Errorf("read response body: %e", err)
	}
	if string(respBody) != "{}" {
		t.Errorf("response body: %q", respBody)
	}
}
