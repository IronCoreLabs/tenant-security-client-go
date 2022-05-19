package tenant_security_client_go

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
)

const version = "0.1" // TODO Auto update this.

const (
	tsp_api_prefix_str             string = "/api/1/"
	wrap_endpoint_str              string = "document/wrap"
	batch_wrap_endpoint_str        string = "document/batch-wrap"
	unwrap_endpoint_str            string = "document/unwrap"
	batch_unwrap_endpoint_str      string = "document/batch-unwrap"
	rekey_endpoint_str             string = "document/rekey"
	tenant_key_derive_endpoint_str string = "key/derive"
	security_event_endpoint_str    string = "event/security-event"
)
var (
	tsp_api_prefix             *url.URL
	wrap_endpoint              *url.URL
	batch_wrap_endpoint        *url.URL
	unwrap_endpoint            *url.URL
	batch_unwrap_endpoint      *url.URL
	rekey_endpoint             *url.URL
	tenant_key_derive_endpoint *url.URL
	security_event_endpoint    *url.URL
)

func init() {
	var err error

	tsp_api_prefix, err = url.Parse(tsp_api_prefix_str)
	if err != nil {
		log.Panicf("Unable to parse tsp_api_prefix %q as relative URL: %e", tsp_api_prefix_str, err)
	}

	wrap_endpoint, err = url.Parse(wrap_endpoint_str)
	if err != nil {
		log.Panicf("Unable to parse wrap_endpoint %q as relative URL: %e", wrap_endpoint_str, err)
	}

	batch_wrap_endpoint, err = url.Parse(batch_wrap_endpoint_str)
	if err != nil {
		log.Panicf("Unable to parse batch_wrap_endpoint %q as relative URL: %e", batch_wrap_endpoint_str, err)
	}

	unwrap_endpoint, err = url.Parse(unwrap_endpoint_str)
	if err != nil {
		log.Panicf("Unable to parse unwrap_endpoint %q as relative URL: %e", unwrap_endpoint_str, err)
	}

	batch_unwrap_endpoint, err = url.Parse(batch_unwrap_endpoint_str)
	if err != nil {
		log.Panicf("Unable to parse batch_unwrap_endpoint %q as relative URL: %e", batch_unwrap_endpoint_str, err)
	}

	rekey_endpoint, err = url.Parse(rekey_endpoint_str)
	if err != nil {
		log.Panicf("Unable to parse rekey_endpoint %q as relative URL: %e", rekey_endpoint_str, err)
	}

	tenant_key_derive_endpoint, err = url.Parse(tenant_key_derive_endpoint_str)
	if err != nil {
		log.Panicf("Unable to parse tenant_key_derive_endpoint %q as relative URL: %e", tenant_key_derive_endpoint_str, err)
	}

	security_event_endpoint, err = url.Parse(security_event_endpoint_str)
	if err != nil {
		log.Panicf("Unable to parse security_event_endpoint %q as relative URL: %e", security_event_endpoint_str, err)
	}
}

type tenantSecurityRequest struct {
	apiKey     string
	tspAddress *url.URL
}

func newTenantSecurityRequest(apiKey string, tspAddress *url.URL) (*tenantSecurityRequest, error) {
	baseUrl := tspAddress.ResolveReference(tsp_api_prefix)
	req := &tenantSecurityRequest{apiKey, baseUrl}
	return req, nil
}

func (r *tenantSecurityRequest) wrapKey() (string, error) {
	reqBody := io.NopCloser(strings.NewReader(`{"tenantId": "tenant-gcp", "iclFields": {"requestingId": "bar"}, "customFields": {}}`))
	req, err := r.newRequest(r.tspAddress.ResolveReference(wrap_endpoint), reqBody)
	if err != nil {
		return "", err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	// TODO Check response codes for errors.
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(respBody), nil
}

func (r *tenantSecurityRequest) newRequest(path *url.URL, body io.ReadCloser) (*http.Request, error) {
	req := http.Request{
		URL: r.tspAddress.ResolveReference(path),
		Body: body,
		Method: http.MethodPost,
		Header: map[string][]string{
			"User-Agent":    {fmt.Sprintf("Tenant Security Client Go %s", version)},
			"Content-Type":  {"application/json"},
			"Accept":        {"application/json"},
			"Authorization": {fmt.Sprintf("cmk %s", r.apiKey)},
		},
	}
	return &req, nil
}
