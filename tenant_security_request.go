package tsc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
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
func (r *tenantSecurityRequest) wrapKey(request WrapKeyRequest) (*WrapKeyResponse, error) {
	var wrapResp WrapKeyResponse
	err := r.parseAndDoRequest(wrapEndpoint, request, &wrapResp)
	if err != nil {
		return nil, err
	}
	return &wrapResp, nil
}

// wrapKey requests the TSP to generate a DEK and an EDEK.
func (r *tenantSecurityRequest) unwrapKey(request UnwrapKeyRequest) (*UnwrapKeyResponse, error) {
	var unwrapResp UnwrapKeyResponse
	err := r.parseAndDoRequest(unwrapEndpoint, request, &unwrapResp)
	if err != nil {
		return nil, err
	}
	return &unwrapResp, nil
}

// Note: the third parameter MUST be passed by reference for this to work.
func (r *tenantSecurityRequest) parseAndDoRequest(endpoint *tspEndpoint, request interface{},
	response interface{}) error {
	requestJSON, err := json.Marshal(request)
	if err != nil {
		return makeCodedError(unableToMakeRequest, err)
	}
	reqBody := io.NopCloser(bytes.NewReader(requestJSON))
	respBody, err := r.doRequest(endpoint, reqBody)
	if err != nil {
		return err
	}
	// Fill the response with the result of this Unmarshal
	err = json.Unmarshal(respBody, &response)
	if err != nil {
		return makeCodedError(unknownError, err)
	}
	return nil
}

// doRequest sends a JSON request body to a TSP endpoint and returns the response body bytes.
// If the request can't be sent, or if the server response code indicates an error, this function
// returns an error instead.
func (r *tenantSecurityRequest) doRequest(endpoint *tspEndpoint, reqBody io.ReadCloser) ([]byte, error) {
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
		tscError := TenantSecurityClientError{}
		defer resp.Body.Close()
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("error retrieving response body with status %d: %w", resp.StatusCode, err)
		}
		err = json.Unmarshal(respBody, &tscError)
		if err != nil {
			return nil, makeCodedError(unknownError, err)
		}
		return nil, &tscError
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, makeCodedError(unknownError, err)
	}
	// Return the body.
	return respBody, nil
}
