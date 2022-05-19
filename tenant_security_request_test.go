package tenant_security_client_go

import (
	"io"
	"net/url"
	"strings"
	"testing"
)

func TestHello(t *testing.T) {
	url, err := url.Parse("http://localhost:1234")
	if err != nil {
		t.Errorf("%e", err)
	}
	r, err := newTenantSecurityRequest("key", url)
	reqBody := io.NopCloser(strings.NewReader(`{}`))
	reqUrl, err := url.Parse("foo")
	if err != nil {
		t.Error(err)
	}
	req, err := r.newRequest(reqUrl, reqBody)
	if err != nil {
		t.Errorf("newRequest: %e", err)
	}
	if req.URL.Path != "/api/1/foo" {
		t.Errorf("Wrong request path. Got %q, expected %q", req.URL.Path, "/api/1/foo")
	}
}
