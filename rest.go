package tenant_security_client_go

import (
	"encoding/base64"
	"encoding/json"
)

type Base64Bytes struct {
	b []byte
}

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

func (b Base64Bytes) MarshalJSON() ([]byte, error) {
	encoded := base64.StdEncoding.EncodeToString(b.b)
	foo, err := json.Marshal(encoded)
	if err != nil {
		return nil, err
	}
	return foo, nil
}

type RequestMetadata struct {
	TenantId     string            `json:"tenantId"`
	IclFields    IclFields         `json:"iclFields"`
	CustomFields map[string]string `json:"customFields"`
}

type IclFields struct {
	RequestingId string `json:"requestingId"`
	DataLabel    string `json:"dataLabel,omitempty"`
	SourceIp     string `json:"sourceIp,omitempty"`
	ObjectId     string `json:"objectId,omitempty"`
	RequestId    string `json:"requestId,omitempty"`
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
	Keys     map[string][]WrapKeyResponse `json:"keys"`
	Failures []TenantSecurityClientError  `json:"failures"` // TODO: this isn't right
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
	Keys     map[string][]UnwrapKeyResponse `json:"keys"`
	Failures []TenantSecurityClientError    `json:"failures"` // TODO: this isn't right
}

type RekeyRequest struct {
	Edek        Edek   `json:"encryptedDocumentKey"`
	NewTenantId string `json:"newTenantId"`
	RequestMetadata
}

type RekeyResponse = WrapKeyResponse

// TODO: need LogSecurityEventRequest
