package tsc

import (
	"encoding/base64"
	"encoding/json"
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

type Dek = Base64Bytes
type Edek = Base64Bytes

type WrapKeyRequest struct {
	RequestMetadata
}

type WrapKeyResponse struct {
	Dek  Dek  `json:"dek"`
	Edek Edek `json:"edek"`
}

type BatchWrapKeyRequest struct {
	DocumentIds []string `json:"documentIds"`
	RequestMetadata
}

type BatchWrapKeyResponse struct {
	Keys     map[string]WrapKeyResponse           `json:"keys"`
	Failures map[string]TenantSecurityClientError `json:"failures"`
}

type UnwrapKeyRequest struct {
	Edek Edek `json:"encryptedDocumentKey"`
	RequestMetadata
}

type UnwrapKeyResponse struct {
	Dek Dek `json:"dek"`
}

type BatchUnwrapKeyRequest struct {
	Edeks map[string][]Edek `json:"edeks"`
	RequestMetadata
}

type BatchUnwrapKeyResponse struct {
	Keys     map[string]UnwrapKeyResponse         `json:"keys"`
	Failures map[string]TenantSecurityClientError `json:"failures"`
}

type RekeyRequest struct {
	Edek        Edek   `json:"encryptedDocumentKey"`
	NewTenantID string `json:"newTenantId"`
	RequestMetadata
}

type RekeyResponse = WrapKeyResponse

// TODO: need LogSecurityEventRequest
