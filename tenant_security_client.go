package tsc

import (
	"net/url"

	"github.com/IronCoreLabs/tenant-security-client-go/crypto"
)

type TenantSecurityClient struct {
	tenantSecurityRequest tenantSecurityRequest
}

func NewTenantSecurityClient(apiKey string, tspAddress *url.URL) (*TenantSecurityClient, error) {
	req := newTenantSecurityRequest(apiKey, tspAddress)
	client := TenantSecurityClient{tenantSecurityRequest: *req}
	return &client, nil
}

func encryptDocument(document *PlaintextDocument, tenantID string, dek []byte) (map[string][]byte, error) {
	encryptedFields := make(map[string][]byte, len(*document))
	var err error
	for fieldName, fieldData := range *document {
		encryptedFields[fieldName], err = crypto.EncryptDocument(fieldData, tenantID, dek)
		if err != nil {
			return nil, err
		}
	}
	return encryptedFields, nil
}

func (r *TenantSecurityClient) Encrypt(document *PlaintextDocument, metadata *RequestMetadata) (*EncryptedDocument, error) {
	wrapKeyResp, err := r.tenantSecurityRequest.wrapKey(WrapKeyRequest{*metadata})
	if err != nil {
		return nil, err
	}
	encryptedFields, err := encryptDocument(document, metadata.TenantID, wrapKeyResp.Dek.b)
	if err != nil {
		return nil, err
	}
	return &EncryptedDocument{EncryptedFields: encryptedFields, Edek: wrapKeyResp.Edek}, nil
}

func (r *TenantSecurityClient) BatchEncrypt(documents map[string]PlaintextDocument, metadata *RequestMetadata) (*BatchEncryptedDocuments, error) {
	documentIds := make([]string, len(documents))
	i := 0
	for k := range documents {
		documentIds[i] = k
		i++
	}
	batchWrapKeyResp, err := r.tenantSecurityRequest.batchWrapKey(BatchWrapKeyRequest{documentIds, *metadata})
	if err != nil {
		return nil, err
	}
	encryptedDocuments := make(map[string]EncryptedDocument, len(batchWrapKeyResp.Keys))
	for documentId, keys := range batchWrapKeyResp.Keys {
		document := documents[documentId]
		encryptedDocument, err := encryptDocument(&document, metadata.TenantID, keys.Dek.b)
		if err != nil {
			return nil, err
		}
		encryptedDocuments[documentId] = EncryptedDocument{encryptedDocument, keys.Edek}
	}
	failures := make(map[string]TenantSecurityClientError, len(batchWrapKeyResp.Failures))
	for documentId, failure := range batchWrapKeyResp.Failures {
		failures[documentId] = failure
	}
	return &BatchEncryptedDocuments{encryptedDocuments, failures}, nil
}
func (r *TenantSecurityClient) BatchDecrypt(documents map[string]EncryptedDocument, metadata *RequestMetadata) (*BatchDecryptedDocuments, error) {
	idsAndEdeks := make(map[string]Edek, len(documents))
	for documentId, document := range documents {
		idsAndEdeks[documentId] = document.Edek
	}
	batchUnwrapKeyResp, err := r.tenantSecurityRequest.batchUnwrapKey(BatchUnwrapKeyRequest{idsAndEdeks, *metadata})
	if err != nil {
		return nil, err
	}
	decryptedDocuments := make(map[string]DecryptedDocument, len(batchUnwrapKeyResp.Keys))
	for documentId, keys := range batchUnwrapKeyResp.Keys {
		document := documents[documentId]
		decryptedDocument, err := decryptDocument(&document, keys.Dek.b)
		if err != nil {
			return nil, err
		}
		decryptedDocuments[documentId] = DecryptedDocument{decryptedDocument, document.Edek}
	}
	failures := make(map[string]TenantSecurityClientError, len(batchUnwrapKeyResp.Failures))
	for documentId, failure := range batchUnwrapKeyResp.Failures {
		failures[documentId] = failure
	}
	return &BatchDecryptedDocuments{decryptedDocuments, failures}, nil

}

func decryptDocument(document *EncryptedDocument, dek []byte) (map[string][]byte, error) {
	decryptedFields := make(map[string][]byte, len(document.EncryptedFields))
	var err error
	for k, v := range document.EncryptedFields {
		decryptedFields[k], err = crypto.DecryptDocument(v, dek)
		if err != nil {
			return nil, err
		}
	}
	return decryptedFields, nil
}

func (r *TenantSecurityClient) Decrypt(document *EncryptedDocument, metadata *RequestMetadata) (*DecryptedDocument, error) {
	unwrapKeyResp, err := r.tenantSecurityRequest.unwrapKey(UnwrapKeyRequest{Edek: document.Edek, RequestMetadata: *metadata})
	if err != nil {
		return nil, err
	}
	decryptedFields, err := decryptDocument(document, unwrapKeyResp.Dek.b)
	if err != nil {
		return nil, err
	}
	return &DecryptedDocument{decryptedFields, document.Edek}, nil
}

type PlaintextDocument = map[string][]byte

type EncryptedDocument struct {
	EncryptedFields map[string][]byte `json:"encryptedFields"`
	Edek            Edek              `json:"edek"`
}

type DecryptedDocument struct {
	DecryptedFields map[string][]byte
	Edek            Edek
}

type BatchEncryptedDocuments struct {
	Documents map[string]EncryptedDocument
	Failures  map[string]TenantSecurityClientError
}

type BatchDecryptedDocuments struct {
	Documents map[string]DecryptedDocument
	Failures  map[string]TenantSecurityClientError
}

//go:generate protoc --go_out=. document_header.proto
