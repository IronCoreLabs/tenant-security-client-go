package tenant_security_client_go

import (
	"net/url"

	"github.com/IronCoreLabs/tenant-security-client-go/crypto"
)

type TenantSecurityClient struct {
	tenantSecurityRequest tenantSecurityRequest
}

func NewTenantSecurityClient(apiKey string, tspAddress *url.URL) (*TenantSecurityClient, error) {
	req, err := newTenantSecurityRequest(apiKey, tspAddress)
	if err != nil {
		return nil, err
	}
	client := TenantSecurityClient{tenantSecurityRequest: *req}
	return &client, nil
}

func (r *TenantSecurityClient) Encrypt(document map[string][]byte, metadata *RequestMetadata) (*EncryptedDocument, error) {
	wrapKeyResp, err := r.tenantSecurityRequest.wrapKey(WrapKeyRequest{*metadata})
	if err != nil {
		return nil, err
	}
	encryptedFields := make(map[string][]byte, len(document))
	for k, v := range document {
		encryptedFields[k], err = crypto.EncryptDocument(v, metadata.TenantId, wrapKeyResp.Dek.b)
		if err != nil { // TODO: bad to just exit like this
			return nil, err
		}
	}
	return &EncryptedDocument{EncryptedFields: encryptedFields, Edek: wrapKeyResp.Edek}, nil
}

func (r *TenantSecurityClient) Decrypt(document *EncryptedDocument, metadata *RequestMetadata) (*PlaintextDocument, error) {

	unwrapKeyResp, err := r.tenantSecurityRequest.unwrapKey(UnwrapKeyRequest{Edek: document.Edek, RequestMetadata: *metadata})

	if err != nil {
		return nil, err
	}
	decryptedFields := make(map[string][]byte, len(document.EncryptedFields))
	for k, v := range document.EncryptedFields {
		decryptedFields[k], err = crypto.DecryptDocument(v, unwrapKeyResp.Dek.b)
		if err != nil { // TODO: bad to just exit like this
			return nil, err
		}
	}
	return &PlaintextDocument{decryptedFields, document.Edek}, nil
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
