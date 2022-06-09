// tsc is the REST client for the IronCore Tenant Security Proxy. This client uses the TSP to perform encryption, decryption, and security logging.
package tsc

import (
	"net/url"
)

// TenantSecurityClient is used to encrypt and decrypt documents, log security events, and more.
// It is the primary class that consumers of the library will need to utilize, and a single instance
// of the class can be re-used for requests across different tenants. This API is safe for
// concurrent use.
type TenantSecurityClient struct {
	tenantSecurityRequest tenantSecurityRequest
}

// NewTenantSecurityClient creates the TenantSecurityClient required for all encryption, decryption, and
// logging operations. It requires the API key used when starting the Tenant Security Proxy (TSP) as well
// as the URL of the TSP.
func NewTenantSecurityClient(apiKey string, tspAddress *url.URL) *TenantSecurityClient {
	req := newTenantSecurityRequest(apiKey, tspAddress)
	client := TenantSecurityClient{tenantSecurityRequest: *req}
	return &client
}

// encryptDocument goes through the fields of the document and encrypts each field.
// The resulting map's keys are identical to the document's fields' keys.
func encryptDocument(document *PlaintextDocument, tenantID string, dek []byte) (map[string][]byte, error) {
	encryptedFields := make(map[string][]byte, len(*document))
	var err error
	for fieldName, fieldData := range *document {
		encryptedFields[fieldName], err = encryptDocumentBytes(fieldData, tenantID, dek)
		if err != nil {
			return nil, err
		}
	}
	return encryptedFields, nil
}

// Encrypt encrypts the provided document. Documents are provided as a map of field ID/name (string)
// to their bytes. Uses the Tenant Security Proxy to generate a new document encryption key (DEK),
// encrypts that key (EDEK), then uses the DEK to encrypt all of the provided document fields.
// Returns an EncryptedDocument which contains a map from each field's ID/name to encrypted bytes
// as well as the EDEK and discards the DEK.
func (r *TenantSecurityClient) Encrypt(document *PlaintextDocument, metadata *RequestMetadata) (*EncryptedDocument, error) {
	wrapKeyResp, err := r.tenantSecurityRequest.wrapKey(wrapKeyRequest{*metadata})
	if err != nil {
		return nil, err
	}
	encryptedFields, err := encryptDocument(document, metadata.TenantID, wrapKeyResp.Dek.b)
	if err != nil {
		return nil, err
	}
	return &EncryptedDocument{EncryptedFields: encryptedFields, Edek: wrapKeyResp.Edek}, nil
}

// EncryptWithExistingKey encrypts the provided document reusing an existing encrypted document encryption key (EDEK).
// Makes a call out to the Tenant Security Proxy to decrypt the EDEK and then uses the resulting
// key (DEK) to encrypt the document. This allows callers to update/re-encrypt data that has
// already been encrypted with an existing key. For example, if multiple columns in a DB row are
// all encrypted to the same key and one of those columns needs to be updated, this method
// allows the caller to update a single column without having to re-encrypt every field in the
// row with a new key.
func (r *TenantSecurityClient) EncryptWithExistingKey(document *DecryptedDocument, metadata *RequestMetadata) (*EncryptedDocument, error) {
	unwrapKeyResp, err := r.tenantSecurityRequest.unwrapKey(unwrapKeyRequest{document.Edek, *metadata})
	if err != nil {
		return nil, err
	}
	encryptedFields, err := encryptDocument(&document.DecryptedFields, metadata.TenantID, unwrapKeyResp.Dek.b)
	if err != nil {
		return nil, err
	}
	return &EncryptedDocument{encryptedFields, document.Edek}, nil
}

// BatchEncrypt encrypts a map of documents from the ID of the document to the map of fields to encrypt.
// Each document will be encrypted to the same tenant ID. Makes a call out to the Tenant Security Proxy
// to generate a collection of new DEK/EDEK pairs for each document ID provided. This function
// supports partial failure so it returns two maps, one of document ID to successfully encrypted
// document and one of document ID to an Error.
func (r *TenantSecurityClient) BatchEncrypt(documents map[string]PlaintextDocument, metadata *RequestMetadata) (*BatchEncryptedDocuments, error) {
	documentIds := make([]string, len(documents))
	i := 0
	for k := range documents {
		documentIds[i] = k
		i++
	}
	batchWrapKeyResp, err := r.tenantSecurityRequest.batchWrapKey(batchWrapKeyRequest{documentIds, *metadata})
	if err != nil {
		return nil, err
	}
	encryptedDocuments := make(map[string]EncryptedDocument, len(batchWrapKeyResp.Keys))
	failures := make(map[string]error, len(batchWrapKeyResp.Failures))
	for documentID, keys := range batchWrapKeyResp.Keys {
		document := documents[documentID]
		encryptedDocument, err := encryptDocument(&document, metadata.TenantID, keys.Dek.b)
		if err != nil {
			failures[documentID] = err
		} else {
			encryptedDocuments[documentID] = EncryptedDocument{encryptedDocument, keys.Edek}
		}
	}
	for documentID := range batchWrapKeyResp.Failures {
		err := batchWrapKeyResp.Failures[documentID]
		failures[documentID] = &err
	}
	return &BatchEncryptedDocuments{encryptedDocuments, failures}, nil
}

// decryptDocument goes through the fields of the document and decrypts each field.
// The resulting map's keys are identical to the document's fields' keys.
func decryptDocument(document *EncryptedDocument, dek []byte) (map[string][]byte, error) {
	decryptedFields := make(map[string][]byte, len(document.EncryptedFields))
	var err error
	for k, v := range document.EncryptedFields {
		decryptedFields[k], err = decryptDocumentBytes(v, dek)
		if err != nil {
			return nil, err
		}
	}
	return decryptedFields, nil
}

// Decrypt decrypts the provided EncryptedDocument. Uses the Tenant Security Proxy to decrypt the
// document's encrypted document key (EDEK) and uses it to decrypt and return the document bytes. The DEK
// is then discarded.
func (r *TenantSecurityClient) Decrypt(document *EncryptedDocument, metadata *RequestMetadata) (*DecryptedDocument, error) {
	unwrapKeyResp, err := r.tenantSecurityRequest.unwrapKey(unwrapKeyRequest{Edek: document.Edek, RequestMetadata: *metadata})
	if err != nil {
		return nil, err
	}
	decryptedFields, err := decryptDocument(document, unwrapKeyResp.Dek.b)
	if err != nil {
		return nil, err
	}
	return &DecryptedDocument{decryptedFields, document.Edek}, nil
}

// BatchDecrypt decrypts a map of documents from the ID of the document to its encrypted content. Makes a call
// out to the Tenant Security Proxy to decrypt all of the EDEKs in each document. This function
// supports partial failure so it returns two maps, one of document ID to successfully decrypted
// document and one of document ID to an Error.
func (r *TenantSecurityClient) BatchDecrypt(documents map[string]EncryptedDocument, metadata *RequestMetadata) (*BatchDecryptedDocuments, error) {
	idsAndEdeks := make(map[string]Edek, len(documents))
	for documentID, document := range documents {
		idsAndEdeks[documentID] = document.Edek
	}
	batchUnwrapKeyResp, err := r.tenantSecurityRequest.batchUnwrapKey(batchUnwrapKeyRequest{idsAndEdeks, *metadata})
	if err != nil {
		return nil, err
	}
	decryptedDocuments := make(map[string]DecryptedDocument, len(batchUnwrapKeyResp.Keys))
	failures := make(map[string]error, len(batchUnwrapKeyResp.Failures))
	for documentID, keys := range batchUnwrapKeyResp.Keys {
		document := documents[documentID]
		decryptedDocument, err := decryptDocument(&document, keys.Dek.b)
		if err != nil {
			failures[documentID] = err
		} else {
			decryptedDocuments[documentID] = DecryptedDocument{decryptedDocument, document.Edek}
		}
	}
	for documentID := range batchUnwrapKeyResp.Failures {
		err := batchUnwrapKeyResp.Failures[documentID]
		failures[documentID] = &err
	}
	return &BatchDecryptedDocuments{decryptedDocuments, failures}, nil
}

// RekeyEdek re-keys a document's encrypted document key (EDEK) to a new tenant. Decrypts the EDEK then re-encrypts it to the
// new tenant. The DEK is then discarded. The old tenant and new tenant can be the same in order to re-key the
// document to the tenant's latest primary config.
func (r *TenantSecurityClient) RekeyEdek(edek *Edek, newTenantID string, metadata *RequestMetadata) (*Edek, error) {
	rekeyResp, err := r.tenantSecurityRequest.rekeyEdek(rekeyRequest{*edek, newTenantID, *metadata})
	if err != nil {
		return nil, err
	}
	return &rekeyResp.Edek, nil
}

// Send the provided security event to the TSP to be logged and analyzed. Note that logging a security event is an
// asynchronous operation at the TSP, so successful receipt of a security event does not mean
// that the event is deliverable or has been delivered to the tenant's logging system; it simply
// means that the event has been received and will be processed.
func (r *TenantSecurityClient) LogSecurityEvent(event SecurityEvent, metadata *EventMetadata) error {
	return r.tenantSecurityRequest.logSecurityEvent(&logSecurityEventRequest{event, *metadata})
}

// PlaintextDocument is a map from field name/ID to the field's bytes.
type PlaintextDocument = map[string][]byte

// EncryptedDocument is a document that has been encrypted by the TenantSecurityClient. It contains a map
// from field name/ID to the encrypted bytes, and the encrypted document encryption key (EDEK) necessary
// for decryption.
type EncryptedDocument struct {
	EncryptedFields map[string][]byte `json:"encryptedFields"`
	Edek            Edek              `json:"edek"`
}

// DecryptedDocument is a document that has been decrypted by the TenantSecurityClient. It contains a map
// from field name/ID to the decrypted bytes, and the encrypted document encryption key (EDEK) used
// for decryption.
type DecryptedDocument struct {
	DecryptedFields map[string][]byte
	Edek            Edek
}

// BatchEncryptedDocuments contains a map from document ID to successfully encrypted
// document and a separate map from document ID to an error.
type BatchEncryptedDocuments struct {
	Documents map[string]EncryptedDocument
	Failures  map[string]error
}

// BatchDecryptedDocuments contains a map from document ID to successfully decrypted
// document and a separate map from document ID to an error.
type BatchDecryptedDocuments struct {
	Documents map[string]DecryptedDocument
	Failures  map[string]error
}

//go:generate protoc --go_out=. document_header.proto
