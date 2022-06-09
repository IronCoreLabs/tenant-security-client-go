package tsc

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMakeJsonRequest(t *testing.T) {
	apiKey := "fake_key"
	endpoint := wrapEndpoint
	handler := http.HandlerFunc(func(writer http.ResponseWriter, r *http.Request) {
		assert.Equal(t, r.URL.Path, "/api/1/document/wrap")
		authHeaders := r.Header["Authorization"]
		assert.Equal(t, len(authHeaders), 1)
		authHeader := authHeaders[0]
		assert.Equal(t, authHeader, "cmk "+apiKey)
		fmt.Fprintf(writer, "{}")
	})
	server := httptest.NewServer(handler)
	defer server.Close()
	url, err := url.Parse(server.URL)
	assert.Nil(t, err)
	r := newTenantSecurityRequest(apiKey, url)
	reqBody := io.NopCloser(strings.NewReader(`{}`))
	respBody, err := r.doRequest(endpoint, reqBody)
	assert.Nil(t, err)
	assert.Equal(t, string(respBody), "{}")
}
