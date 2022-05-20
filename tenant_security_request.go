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

// Paths that refer to TSP REST endpoints.
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

var tsp_api_prefix *url.URL

type tspEndpoint url.URL

// These values can be used like an enum of valid TSP endpoints.
var (
	wrap_endpoint              *tspEndpoint
	batch_wrap_endpoint        *tspEndpoint
	unwrap_endpoint            *tspEndpoint
	batch_unwrap_endpoint      *tspEndpoint
	rekey_endpoint             *tspEndpoint
	tenant_key_derive_endpoint *tspEndpoint
	security_event_endpoint    *tspEndpoint
)

func init() {
	var err error
	tsp_api_prefix, err = url.Parse(tsp_api_prefix_str)
	if err != nil {
		log.Panicf("Unable to parse tsp_api_prefix_str %q as relative URL: %e", tsp_api_prefix_str, err)
	}

	parseUrl := func(urlStr, name string) *tspEndpoint {
		url, err := url.Parse(urlStr)
		if err != nil {
			log.Panicf("Unable to parse %s %q as relative URL: %e", name, urlStr, err)
		}
		return (*tspEndpoint)(url)
	}

	wrap_endpoint = parseUrl(wrap_endpoint_str, "wrap_endpoint")
	batch_wrap_endpoint = parseUrl(batch_wrap_endpoint_str, "batch_wrap_endpoint")
	unwrap_endpoint = parseUrl(unwrap_endpoint_str, "unwrap_endpoint")
	batch_unwrap_endpoint = parseUrl(batch_unwrap_endpoint_str, "batch_unwrap_endpoint")
	rekey_endpoint = parseUrl(rekey_endpoint_str, "rekey_endpoint")
	tenant_key_derive_endpoint = parseUrl(tenant_key_derive_endpoint_str, "tenant_key_derive_endpoint")
	security_event_endpoint = parseUrl(security_event_endpoint_str, "security_event_endpoint")
}

// tenantSecurityRequest is a long-lived object that sends and receives HTTP requests to the TSP.
type tenantSecurityRequest struct {
	apiKey string
	// Address of the TSP, including the API prefix
	tspAddress *url.URL
}

func newTenantSecurityRequest(apiKey string, tspAddress *url.URL) (*tenantSecurityRequest, error) {
	baseUrl := tspAddress.ResolveReference(tsp_api_prefix)
	req := &tenantSecurityRequest{apiKey, baseUrl}
	return req, nil
}

// wrapKey requests the TSP to generate a DEK and an EDEK.
func (r *tenantSecurityRequest) wrapKey() (string, error) {
	reqBody := io.NopCloser(strings.NewReader(`{"tenantId": "tenant-gcp", "iclFields": {"requestingId": "bar"}, "customFields": {}}`))
	resp, err := r.makeJsonRequest(wrap_endpoint, reqBody)
	if err != nil {
		return "", err
	}
	defer resp.Close()

	respBody, err := io.ReadAll(resp)
	if err != nil {
		return "", err
	}

	return string(respBody), nil
}

// makeJsonRequest sends a JSON request body to a TSP endpoint and returns the response body. If the request can't be sent, or if
// the server response code indicates an error, this function returns an error instead. Caller is responsible for closing the
// response body.
func (r *tenantSecurityRequest) makeJsonRequest(endpoint *tspEndpoint, reqBody io.ReadCloser) (io.ReadCloser, error) {
	// Build the request.
	url := r.tspAddress.ResolveReference((*url.URL)(endpoint))
	req := http.Request{
		URL:    url,
		Method: http.MethodPost,
		Body:   reqBody,
		Header: map[string][]string{
			"User-Agent":    {fmt.Sprintf("Tenant Security Client Go %s", version)},
			"Content-Type":  {"application/json"},
			"Accept":        {"application/json"},
			"Authorization": {fmt.Sprintf("cmk %s", r.apiKey)},
		},
	}

	// Perform the request.
	resp, err := http.DefaultClient.Do(&req)
	if err != nil {
		return nil, fmt.Errorf("POST to %q: %e", url, err)
	}

	// Check the response code.
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("POST to %q: %s", url, http.StatusText(resp.StatusCode))
	}

	// Return the body.
	return resp.Body, nil
}
