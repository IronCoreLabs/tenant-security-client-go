package tsc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
)

// Paths that refer to TSP REST endpoints.
const (
	tspAPIPrefixString       string = "/api/1/"
	wrapEndpointStr          string = "document/wrap"
	batchWrapEndpointStr     string = "document/batch-wrap"
	unwrapEndpointStr        string = "document/unwrap"
	batchUnwrapEndpointStr   string = "document/batch-unwrap"
	rekeyEndpointStr         string = "document/rekey"
	securityEventEndpointStr string = "event/security-event"
)

var tspAPIPrefix *url.URL

type tspEndpoint url.URL

// These values can be used like an enum of valid TSP endpoints.
var (
	wrapEndpoint          *tspEndpoint
	batchWrapEndpoint     *tspEndpoint
	unwrapEndpoint        *tspEndpoint
	batchUnwrapEndpoint   *tspEndpoint
	rekeyEndpoint         *tspEndpoint
	securityEventEndpoint *tspEndpoint
)

func init() {
	var err error
	tspAPIPrefix, err = url.Parse(tspAPIPrefixString)
	if err != nil {
		log.Panicf("Unable to parse tspAPIPrefixString %q as relative URL: %v", tspAPIPrefixString, err)
	}

	parseURL := func(urlStr, name string) *tspEndpoint {
		url, err := url.Parse(urlStr)
		if err != nil {
			log.Panicf("Unable to parse %s %q as relative URL: %v", name, urlStr, err)
		}
		return (*tspEndpoint)(url)
	}

	wrapEndpoint = parseURL(wrapEndpointStr, "wrapEndpoint")
	batchWrapEndpoint = parseURL(batchWrapEndpointStr, "batchWrapEndpoint")
	unwrapEndpoint = parseURL(unwrapEndpointStr, "unwrapEndpoint")
	batchUnwrapEndpoint = parseURL(batchUnwrapEndpointStr, "batchUnwrapEndpoint")
	rekeyEndpoint = parseURL(rekeyEndpointStr, "rekeyEndpoint")
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
func (r *tenantSecurityRequest) wrapKey(ctx context.Context, request wrapKeyRequest) (*wrapKeyResponse, error) {
	var wrapResp wrapKeyResponse
	err := r.parseAndDoRequest(ctx, wrapEndpoint, request, &wrapResp)
	if err != nil {
		return nil, err
	}
	return &wrapResp, nil
}

func (r *tenantSecurityRequest) batchWrapKey(ctx context.Context,
	request batchWrapKeyRequest) (*batchWrapKeyResponse, error) {
	var batchWrapResp batchWrapKeyResponse
	err := r.parseAndDoRequest(ctx, batchWrapEndpoint, request, &batchWrapResp)
	if err != nil {
		return nil, err
	}
	return &batchWrapResp, nil
}

// wrapKey requests the TSP to generate a DEK and an EDEK.
func (r *tenantSecurityRequest) unwrapKey(ctx context.Context, request unwrapKeyRequest) (*unwrapKeyResponse, error) {
	var unwrapResp unwrapKeyResponse
	err := r.parseAndDoRequest(ctx, unwrapEndpoint, request, &unwrapResp)
	if err != nil {
		return nil, err
	}
	return &unwrapResp, nil
}

func (r *tenantSecurityRequest) batchUnwrapKey(ctx context.Context,
	request batchUnwrapKeyRequest) (*batchUnwrapKeyResponse, error) {
	var batchUnwrapResp batchUnwrapKeyResponse
	err := r.parseAndDoRequest(ctx, batchUnwrapEndpoint, request, &batchUnwrapResp)
	if err != nil {
		return nil, err
	}
	return &batchUnwrapResp, nil
}

func (r *tenantSecurityRequest) rekeyEdek(ctx context.Context, request rekeyRequest) (*rekeyResponse, error) {
	var rekeyResp rekeyResponse
	err := r.parseAndDoRequest(ctx, rekeyEndpoint, request, &rekeyResp)
	if err != nil {
		return nil, err
	}
	return &rekeyResp, nil
}

func (r *tenantSecurityRequest) logSecurityEvent(ctx context.Context, request *logSecurityEventRequest) error {
	return r.parseAndDoRequest(ctx, securityEventEndpoint, request, nil)
}

// Note: the third parameter MUST be passed by reference for this to work.
func (r *tenantSecurityRequest) parseAndDoRequest(ctx context.Context, endpoint *tspEndpoint, request interface{},
	response interface{}) error {
	requestJSON, err := json.Marshal(request)
	if err != nil {
		return makeErrorf(errorKindLocal, "marshal JSON request: %w", err)
	}
	reqBody := bytes.NewReader(requestJSON)
	respBody, err := r.doRequest(ctx, endpoint, reqBody)
	if err != nil {
		return err
	}
	// Fill the response with the result of this Unmarshal
	err = json.Unmarshal(respBody, &response)
	if err != nil {
		return makeErrorf(errorKindLocal, "unmarshal JSON response: %w", err)
	}
	return nil
}

// doRequest sends a JSON request body to a TSP endpoint and returns the response body bytes.
// If the request can't be sent, or if the server response code indicates an error, this function
// returns an error instead.
func (r *tenantSecurityRequest) doRequest(ctx context.Context,
	endpoint *tspEndpoint,
	reqBody io.Reader) ([]byte, error) {
	// Build the request.
	url := r.tspAddress.ResolveReference((*url.URL)(endpoint))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url.String(), reqBody)
	if err != nil {
		return nil, makeErrorf(errorKindNetwork, "new request to %q: %w", url, err)
	}
	req.Header = map[string][]string{
		"User-Agent":    {fmt.Sprintf("Tenant Security Client Go v%s", Version)},
		"Content-Type":  {"application/json"},
		"Accept":        {"application/json"},
		"Authorization": {fmt.Sprintf("cmk %s", r.apiKey)},
	}

	// Perform the request.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, makeErrorf(errorKindNetwork, "%w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, makeErrorf(errorKindNetwork, "read TSP response body (HTTP status %d): %w", resp.StatusCode, err)
	}

	// Check the response code.
	if resp.StatusCode >= http.StatusBadRequest {
		tscError := Error{}
		err = json.Unmarshal(respBody, &tscError)
		if err != nil {
			return nil, makeErrorf(errorKindNetwork, "unmarshal TSP error response (HTTP status %d): %w", resp.StatusCode, err)
		}
		return nil, &tscError
	}

	// Return the body.
	return respBody, nil
}
