package tsc

import (
	"net/url"
)

type TenantSecurityClient struct {
	tenantSecurityRequest tenantSecurityRequest
}

func NewTenantSecurityClient(apiKey string, tspAddress *url.URL) *TenantSecurityClient {
	req := newTenantSecurityRequest(apiKey, tspAddress)
	client := TenantSecurityClient{tenantSecurityRequest: *req}
	return &client
}

func (r *TenantSecurityClient) Encrypt(document map[string][]byte,
	metadata *RequestMetadata) (*EncryptedDocument, error) {
	wrapKeyResp, err := r.tenantSecurityRequest.wrapKey(wrapKeyRequest{*metadata})
	if err != nil {
		return nil, err
	}
	encryptedFields := make(map[string][]byte, len(document))
	for k, v := range document {
		encryptedFields[k], err = encryptDocument(v, metadata.TenantID, wrapKeyResp.Dek.b)
		if err != nil {
			return nil, err
		}
	}
	return &EncryptedDocument{EncryptedFields: encryptedFields, Edek: wrapKeyResp.Edek}, nil
}

func (r *TenantSecurityClient) Decrypt(document *EncryptedDocument, metadata *RequestMetadata) (*PlaintextDocument, error) {

	unwrapKeyResp, err := r.tenantSecurityRequest.unwrapKey(
		unwrapKeyRequest{Edek: document.Edek, RequestMetadata: *metadata})

	if err != nil {
		return nil, err
	}
	decryptedFields := make(map[string][]byte, len(document.EncryptedFields))
	for k, v := range document.EncryptedFields {
		decryptedFields[k], err = decryptDocument(v, unwrapKeyResp.Dek.b)
		if err != nil {
			return nil, err
		}
	}
	return &PlaintextDocument{decryptedFields, document.Edek}, nil
}

func (r *TenantSecurityClient) LogSecurityEvent(event SecurityEvent, metadata *EventMetadata) error {
	return r.tenantSecurityRequest.logSecurityEvent(&logSecurityEventRequest{event, *metadata})
}

type PlaintextDocument struct {
	DecryptedFields map[string][]byte
	Edek            Edek
}

type EncryptedDocument struct {
	EncryptedFields map[string][]byte `json:"encryptedFields"`
	Edek            Edek              `json:"edek"`
}

//go:generate protoc --go_out=. document_header.proto
