package tsc

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
)

// Paths that refer to TSP REST endpoints.
const (
	tspAPIPrefixString         string = "/api/1/"
	wrapEndpointStr            string = "document/wrap"
	batchWrapEndpointStr       string = "document/batch-wrap"
	unwrapEndpointStr          string = "document/unwrap"
	batchUnwrapEndpointStr     string = "document/batch-unwrap"
	rekeyEndpointStr           string = "document/rekey"
	tenantKeyDeriveEndpointStr string = "key/derive"
	securityEventEndpointStr   string = "event/security-event"
)

var tspAPIPrefix *url.URL

type tspEndpoint url.URL

// These values can be used like an enum of valid TSP endpoints.
var (
	wrapEndpoint            *tspEndpoint
	batchWrapEndpoint       *tspEndpoint
	unwrapEndpoint          *tspEndpoint
	batchUnwrapEndpoint     *tspEndpoint
	rekeyEndpoint           *tspEndpoint
	tenantKeyDeriveEndpoint *tspEndpoint
	securityEventEndpoint   *tspEndpoint
)

func init() {
	var err error
	tspAPIPrefix, err = url.Parse(tspAPIPrefixString)
	if err != nil {
		log.Panicf("Unable to parse tspAPIPrefixString %q as relative URL: %e", tspAPIPrefixString, err)
	}

	parseURL := func(urlStr, name string) *tspEndpoint {
		url, err := url.Parse(urlStr)
		if err != nil {
			log.Panicf("Unable to parse %s %q as relative URL: %e", name, urlStr, err)
		}
		return (*tspEndpoint)(url)
	}

	wrapEndpoint = parseURL(wrapEndpointStr, "wrapEndpoint")
	batchWrapEndpoint = parseURL(batchWrapEndpointStr, "batchWrapEndpoint")
	unwrapEndpoint = parseURL(unwrapEndpointStr, "unwrapEndpoint")
	batchUnwrapEndpoint = parseURL(batchUnwrapEndpointStr, "batchUnwrapEndpoint")
	rekeyEndpoint = parseURL(rekeyEndpointStr, "rekeyEndpoint")
	tenantKeyDeriveEndpoint = parseURL(tenantKeyDeriveEndpointStr, "tenantKeyDeriveEndpoint")
	securityEventEndpoint = parseURL(securityEventEndpointStr, "securityEventEndpoint")
}

// tenantSecurityRequest is a long-lived object that sends and receives HTTP requests to the TSP.
type tenantSecurityRequest struct {
	apiKey string
	// Address of the TSP, including the API prefix
	tspAddress *url.URL
}

func newTenantSecurityRequest(apiKey string, tspAddress *url.URL) *tenantSecurityRequest {
	baseURL := tspAddress.ResolveReference(tspAPIPrefix)
	req := &tenantSecurityRequest{apiKey, baseURL}
	return req
}

// wrapKey requests the TSP to generate a DEK and an EDEK.
func (r *tenantSecurityRequest) wrapKey() (string, error) {
	reqBody := io.NopCloser(strings.NewReader(`{"tenantId": "tenant-gcp", "iclFields": {"requestingId": "bar"}, "customFields": {}}`))
	resp, err := r.makeJSONRequest(wrapEndpoint, reqBody)
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

// makeJSONRequest sends a JSON request body to a TSP endpoint and returns the response body. If the request can't be sent, or if
// the server response code indicates an error, this function returns an error instead. Caller is responsible for closing the
// response body.
func (r *tenantSecurityRequest) makeJSONRequest(endpoint *tspEndpoint, reqBody io.ReadCloser) (io.ReadCloser, error) {
	// Build the request.
	url := r.tspAddress.ResolveReference((*url.URL)(endpoint))
	req := http.Request{
		URL:    url,
		Method: http.MethodPost,
		Body:   reqBody,
		Header: map[string][]string{
			"User-Agent":    {fmt.Sprintf("Tenant Security Client Go v%s", Version)},
			"Content-Type":  {"application/json"},
			"Accept":        {"application/json"},
			"Authorization": {fmt.Sprintf("cmk %s", r.apiKey)},
		},
	}

	// Perform the request.
	resp, err := http.DefaultClient.Do(&req)
	if err != nil {
		return nil, fmt.Errorf("POST to %q: %w", url, err)
	}

	// Check the response code.
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("POST to %q: %s", url, http.StatusText(resp.StatusCode))
	}

	// Return the body.
	return resp.Body, nil
}
