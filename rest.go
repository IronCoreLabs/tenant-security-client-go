package tsc

import (
	"encoding/base64"
	"encoding/json"
	"time"
)

type Base64Bytes struct {
	b []byte
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
	b.b = decoded
	return nil
}

//nolint:wrapcheck // Because this function is called by json code, it should return a json error.
func (b Base64Bytes) MarshalJSON() ([]byte, error) {
	encodedStr := base64.StdEncoding.EncodeToString(b.b)
	encoded, err := json.Marshal(encodedStr)
	if err != nil {
		return nil, err
	}
	return encoded, nil
}

type RequestMetadata struct {
	TenantID     string            `json:"tenantId"`
	IclFields    IclFields         `json:"iclFields"`
	CustomFields map[string]string `json:"customFields"`
}

type IclFields struct {
	RequestingID string `json:"requestingId"`
	DataLabel    string `json:"dataLabel,omitempty"`
	SourceIP     string `json:"sourceIp,omitempty"`
	ObjectID     string `json:"objectId,omitempty"`
	RequestID    string `json:"requestId,omitempty"`
}

type EventMetadata struct {
	TimestampMillis *int `json:"timestampMillis"`
	RequestMetadata
}

type Dek = Base64Bytes
type Edek = Base64Bytes

type wrapKeyRequest struct {
	RequestMetadata
}

type wrapKeyResponse struct {
	Dek  Dek  `json:"dek"`
	Edek Edek `json:"edek"`
}

type batchWrapKeyRequest struct {
	DocumentIds []string `json:"documentIds"`
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

//nolint:wrapcheck // Because this function is called by json code, it should return a json error.
// TSP requires `event` to be beside the `iclFields`.
func (l logSecurityEventRequest) MarshalJSON() ([]byte, error) {
	// If time is `nil`, use the current time
	var timestampMillis int
	if l.TimestampMillis == nil {
		timestampMillis = int(time.Now().UnixMilli())
	} else {
		timestampMillis = *l.TimestampMillis
	}
	type iclFieldsWithEvent struct {
		Event SecurityEvent `json:"event"`
		IclFields
	}
	request := struct {
		TimestampMillis int                `json:"timestampMillis"`
		TenantID        string             `json:"tenantId"`
		IclFields       iclFieldsWithEvent `json:"iclFields"`
		CustomFields    map[string]string  `json:"customFields"`
	}{TimestampMillis: timestampMillis, TenantID: l.TenantID, IclFields: iclFieldsWithEvent{Event: l.Event, IclFields: l.IclFields}, CustomFields: l.CustomFields}
	encoded, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	return encoded, nil
}
