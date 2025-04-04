package tsc

import (
	"encoding/base64"
	"encoding/json"
	"time"
)

// Base64Bytes represents the base64-encoded bytes sent to/from the Tenant Security Proxy.
type Base64Bytes struct {
	Bytes []byte
}

//nolint:wrapcheck // Because this function is called by json code, it should return a json error.
func (b *Base64Bytes) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	decoded, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return err
	}
	b.Bytes = decoded
	return nil
}

//nolint:wrapcheck // Because this function is called by json code, it should return a json error.
func (b Base64Bytes) MarshalJSON() ([]byte, error) {
	encodedStr := base64.StdEncoding.EncodeToString(b.Bytes)
	encoded, err := json.Marshal(encodedStr)
	if err != nil {
		return nil, err
	}
	return encoded, nil
}

// RequestMetadata holds metadata fields as part of a request. Each request has metadata associated with it
// that will be sent to the Tenant Security Proxy for logging and other purposes. Some examples include
// the tenant ID associated with the request, the service that is accessing the data, and a unique ID
// for the request.
type RequestMetadata struct {
	// TenantID is the unique ID of the tenant the action is being performed for.
	TenantID string `json:"tenantId"`
	// IclFields is metadata about the request for the Tenant Security Proxy to log.
	IclFields IclFields `json:"iclFields"`
	// CustomFields is optional additional information for the Tenant Security Proxy to log.
	CustomFields map[string]string `json:"customFields"`
}

// IclFields holds metadata to pass to the Tenant Security Proxy for logging purposes.
type IclFields struct {
	// RequestingID (required) is the unique ID of user/service that is processing data.
	RequestingID string `json:"requestingId"`
	// DataLabel (optional) is the classification of data being processed.
	DataLabel string `json:"dataLabel,omitempty"`
	// SourceIP (optional) is the IP address of the initiator of this document request.
	SourceIP string `json:"sourceIp,omitempty"`
	// ObjectID (optional) is the ID of the object/document being acted on in the host system.
	ObjectID string `json:"objectId,omitempty"`
	// RequestID (optional) is the unique ID that ties the application request ID to Tenant Security Proxy logs.
	RequestID string `json:"requestId,omitempty"`
}

// EventMetadata is metadata associated with the LogSecurityEvent function. It is the same as RequestMetadata
// with the addition of the time at which the event occurred.
type EventMetadata struct {
	// Time when the event occurred.
	TimestampMillis time.Time `json:"timestampMillis"`
	RequestMetadata
}

// Dek is the Document Encryption Key generated by the Tenant Security Proxy.
type Dek = Base64Bytes

// Edek is the Encrypted Document Encryption Key generated by the Tenant Security Proxy.
type Edek = Base64Bytes

type wrapKeyRequest struct {
	RequestMetadata
}

type wrapKeyResponse struct {
	Dek  Dek  `json:"dek"`
	Edek Edek `json:"edek"`
}

type batchWrapKeyRequest struct {
	DocumentIDs []string `json:"documentIds"`
	RequestMetadata
}

type batchWrapKeyResponse struct {
	Keys     map[string]wrapKeyResponse `json:"keys"`
	Failures map[string]Error           `json:"failures"`
}

type unwrapKeyRequest struct {
	Edek Edek `json:"encryptedDocumentKey"`
	RequestMetadata
}

type unwrapKeyResponse struct {
	Dek Dek `json:"dek"`
}

type batchUnwrapKeyRequest struct {
	Edeks map[string]Edek `json:"edeks"`
	RequestMetadata
}

type batchUnwrapKeyResponse struct {
	Keys     map[string]unwrapKeyResponse `json:"keys"`
	Failures map[string]Error             `json:"failures"`
}

type rekeyRequest struct {
	Edek        Edek   `json:"encryptedDocumentKey"`
	NewTenantID string `json:"newTenantId"`
	RequestMetadata
}

type rekeyResponse = wrapKeyResponse

type logSecurityEventRequest struct {
	Event SecurityEvent
	EventMetadata
}

// TSP requires `event` to be beside the `iclFields`.
//
//nolint:wrapcheck // Because this function is called by json code, it should return a json error.
func (l logSecurityEventRequest) MarshalJSON() ([]byte, error) {
	type iclFieldsWithEvent struct {
		Event SecurityEvent `json:"event"`
		IclFields
	}
	request := struct {
		TimestampMillis int                `json:"timestampMillis"`
		TenantID        string             `json:"tenantId"`
		IclFields       iclFieldsWithEvent `json:"iclFields"`
		CustomFields    map[string]string  `json:"customFields"`
	}{
		TimestampMillis: int(l.TimestampMillis.UnixMilli()),
		TenantID:        l.TenantID,
		IclFields:       iclFieldsWithEvent{Event: l.Event, IclFields: l.IclFields},
		CustomFields:    l.CustomFields}
	encoded, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	return encoded, nil
}
