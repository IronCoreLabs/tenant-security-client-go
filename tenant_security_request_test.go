package tenant_security_client_go

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
	endpoint := wrap_endpoint

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

		fmt.Fprintf(w, "{}")
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	url, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	r, err := newTenantSecurityRequest(apiKey, url)
	reqBody := io.NopCloser(strings.NewReader(`{}`))
	resp, err := r.makeJsonRequest(endpoint, reqBody)
	if err != nil {
		t.Errorf("newRequest: %e", err)
	}
	defer resp.Close()
	respBody, err := io.ReadAll(resp)
	if err != nil {
		t.Errorf("read response body: %e", err)
	}
	if string(respBody) != "{}" {
		t.Errorf("response body: %q", respBody)
	}
}
