// tsc is the REST client for the IronCore Tenant Security Proxy. This client uses the TSP to perform encryption,
// decryption, and security logging.
package tsc

import (
	"context"
	"net/url"
	"runtime"
)

// TenantSecurityClient is used to encrypt and decrypt documents, log security events, and more.
// It is the primary class that consumers of the library will need to utilize, and a single instance
// of the class can be re-used for requests across different tenants. This API is safe for
// concurrent use.
type TenantSecurityClient struct {
	tenantSecurityRequest tenantSecurityRequest
	workers               chan struct{}
}

// NewTenantSecurityClient creates the TenantSecurityClient required for all encryption, decryption, and
// logging operations. It requires the API key used when starting the Tenant Security Proxy (TSP) as well
// as the URL of the TSP. Parallelism sets the number of CPU-bound workers which can simultaneously be
// running as a result of BatchEncrypt and BatchDecrypt calls.
func NewTenantSecurityClient(apiKey string, tspAddress *url.URL, parallelism int) *TenantSecurityClient {
	req := newTenantSecurityRequest(apiKey, tspAddress)

	if parallelism == 0 {
		parallelism = runtime.GOMAXPROCS(0) + 1
	}
	workers := make(chan struct{}, parallelism)
	// Initialize the pool of worker tokens by adding that many to the channel.
	for i := 0; i < parallelism; i++ {
		workers <- struct{}{}
	}

	client := TenantSecurityClient{tenantSecurityRequest: *req, workers: workers}
	return &client
}

// encryptDocument goes through the fields of the document and encrypts each field.
// The resulting map's keys are identical to the document's fields' keys.
func (r *TenantSecurityClient) encryptDocument(ctx context.Context,
	document PlaintextDocument,
	tenantID string,
	dek []byte) (map[string][]byte, error) {
	encryptedFields := make(map[string][]byte, len(document))

	// Concurrently handle all the fields.
	type resultType struct {
		fieldName string
		fieldData []byte
		err       error
	}
	results := make(chan resultType)
	for fieldName, fieldData := range document {
		go func(fieldName string, fieldData []byte) {
			result := resultType{fieldName: fieldName}
			select {
			// Context is cancelled, so we need to exit.
			case <-ctx.Done():
				result.err = ctx.Err()
			// A worker token is available, so we can do the work and return the token to the pool.
			case token := <-r.workers:
				result.fieldData, result.err = encryptDocumentBytes(fieldData, tenantID, dek)
				r.workers <- token
			}
			results <- result
		}(fieldName, fieldData)
	}

	// Receive the results as they're available.
	var err error
	for i := 0; i < len(document); i++ {
		result := <-results
		if result.err != nil {
			// Take the first error; ignore the rest.
			if err == nil {
				err = result.err
			}
		} else {
			encryptedFields[result.fieldName] = result.fieldData
		}
	}
	if err != nil {
		return nil, err
	}
	return encryptedFields, nil
}

func (r *TenantSecurityClient) Encrypt(ctx context.Context,
	document PlaintextDocument,
	metadata *RequestMetadata) (*EncryptedDocument, error) {
	wrapKeyResp, err := r.tenantSecurityRequest.wrapKey(ctx, wrapKeyRequest{*metadata})
	if err != nil {
		return nil, err
	}
	encryptedFields, err := r.encryptDocument(ctx, document, metadata.TenantID, wrapKeyResp.Dek.Bytes)
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
func (r *TenantSecurityClient) EncryptWithExistingKey(ctx context.Context,
	document *DecryptedDocument,
	metadata *RequestMetadata) (
	*EncryptedDocument, error) {
	unwrapKeyResp, err := r.tenantSecurityRequest.unwrapKey(ctx, unwrapKeyRequest{document.Edek, *metadata})
	if err != nil {
		return nil, err
	}
	encryptedFields, err := r.encryptDocument(ctx, document.DecryptedFields, metadata.TenantID, unwrapKeyResp.Dek.Bytes)
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
func (r *TenantSecurityClient) BatchEncrypt(ctx context.Context,
	documents map[string]PlaintextDocument,
	metadata *RequestMetadata) (*BatchEncryptedDocuments, error) {
	// Get document IDs into the form required by batchWrapKey.
	documentIds := make([]string, len(documents))
	i := 0
	for k := range documents {
		documentIds[i] = k
		i++
	}

	encryptedDocuments := make(map[string]EncryptedDocument)
	failures := make(map[string]error)

	// Get the keys.
	batchWrapKeyResp, err := r.tenantSecurityRequest.batchWrapKey(ctx, batchWrapKeyRequest{documentIds, *metadata})
	if err != nil {
		return nil, err
	}
	for documentID := range batchWrapKeyResp.Failures {
		err := batchWrapKeyResp.Failures[documentID]
		failures[documentID] = &err
	}

	// Concurrently handle all the documents.
	type resultType struct {
		docID string
		doc   EncryptedDocument
		err   error
	}
	results := make(chan resultType)
	for documentID, keys := range batchWrapKeyResp.Keys {
		go func(docId string, document PlaintextDocument, keys wrapKeyResponse) {
			fields, err := r.encryptDocument(ctx, document, metadata.TenantID, keys.Dek.Bytes)
			doc := EncryptedDocument{EncryptedFields: fields, Edek: keys.Edek}
			results <- resultType{docID: docId, doc: doc, err: err}
		}(documentID, documents[documentID], keys)
	}

	// Receive the results as they're available.
	for i := 0; i < len(batchWrapKeyResp.Keys); i++ {
		result := <-results
		if result.err != nil {
			failures[result.docID] = result.err
		} else {
			encryptedDocuments[result.docID] = result.doc
		}
	}

	return &BatchEncryptedDocuments{encryptedDocuments, failures}, nil
}

// decryptDocument goes through the fields of the document and decrypts each field.
// The resulting map's keys are identical to the document's fields' keys.
func (r *TenantSecurityClient) decryptDocument(ctx context.Context,
	encryptedFields map[string][]byte,
	dek []byte) (map[string][]byte, error) {
	decryptedFields := make(map[string][]byte, len(encryptedFields))

	// Concurrently handle all the fields.
	type resultType struct {
		fieldName string
		fieldData []byte
		err       error
	}
	results := make(chan resultType)
	for fieldName, fieldData := range encryptedFields {
		go func(fieldName string, fieldData []byte) {
			result := resultType{fieldName: fieldName}
			select {
			// Context is cancelled, so we need to exit.
			case <-ctx.Done():
				result.err = ctx.Err()
			// A worker token is available, so we can do the work and return the token to the pool.
			case token := <-r.workers:
				result.fieldData, result.err = decryptDocumentBytes(fieldData, dek)
				r.workers <- token
			}
			results <- result
		}(fieldName, fieldData)
	}

	// Receive the results as they're available.
	var err error
	for i := 0; i < len(encryptedFields); i++ {
		result := <-results
		if result.err != nil {
			if err == nil {
				err = result.err
			}
		} else {
			decryptedFields[result.fieldName] = result.fieldData
		}
	}
	if err != nil {
		return nil, err
	}
	return decryptedFields, nil
}

// Decrypt decrypts the provided EncryptedDocument. Uses the Tenant Security Proxy to decrypt the
// document's encrypted document key (EDEK) and uses it to decrypt and return the document bytes. The DEK
// is then discarded.
func (r *TenantSecurityClient) Decrypt(ctx context.Context,
	document *EncryptedDocument,
	metadata *RequestMetadata) (*DecryptedDocument, error) {
	unwrapKeyResp, err := r.tenantSecurityRequest.unwrapKey(ctx,
		unwrapKeyRequest{Edek: document.Edek, RequestMetadata: *metadata})
	if err != nil {
		return nil, err
	}
	decryptedFields, err := r.decryptDocument(ctx, document.EncryptedFields, unwrapKeyResp.Dek.Bytes)
	if err != nil {
		return nil, err
	}
	return &DecryptedDocument{decryptedFields, document.Edek}, nil
}

// BatchDecrypt decrypts a map of documents from the ID of the document to its encrypted content. Makes a call
// out to the Tenant Security Proxy to decrypt all of the EDEKs in each document. This function
// supports partial failure so it returns two maps, one of document ID to successfully decrypted
// document and one of document ID to an Error.
func (r *TenantSecurityClient) BatchDecrypt(ctx context.Context,
	documents map[string]EncryptedDocument,
	metadata *RequestMetadata) (*BatchDecryptedDocuments, error) {
	// Get IDs and EDEKs into the form required by batchUnwrapKey.
	idsAndEdeks := make(map[string]Edek, len(documents))
	for documentID, document := range documents {
		idsAndEdeks[documentID] = document.Edek
	}

	decryptedDocuments := make(map[string]DecryptedDocument)
	failures := make(map[string]error)

	// Get the keys.
	batchUnwrapKeyResp, err := r.tenantSecurityRequest.batchUnwrapKey(ctx, batchUnwrapKeyRequest{idsAndEdeks, *metadata})
	if err != nil {
		return nil, err
	}
	for documentID := range batchUnwrapKeyResp.Failures {
		err := batchUnwrapKeyResp.Failures[documentID]
		failures[documentID] = &err
	}

	// Concurrently handle all the documents.
	type resultType struct {
		docID string
		doc   DecryptedDocument
		err   error
	}
	results := make(chan resultType)
	for documentID, keys := range batchUnwrapKeyResp.Keys {
		doc := documents[documentID]
		go func(docId string, document *EncryptedDocument, dek []byte) {
			fields, err := r.decryptDocument(ctx, document.EncryptedFields, dek)
			doc := DecryptedDocument{DecryptedFields: fields, Edek: document.Edek}
			results <- resultType{docID: docId, doc: doc, err: err}
		}(documentID, &doc, keys.Dek.Bytes)
	}

	// Receive the results as they're available.
	for i := 0; i < len(batchUnwrapKeyResp.Keys); i++ {
		result := <-results
		if result.err != nil {
			failures[result.docID] = result.err
		} else {
			decryptedDocuments[result.docID] = result.doc
		}
	}

	return &BatchDecryptedDocuments{decryptedDocuments, failures}, nil
}

// RekeyEdek re-keys a document's encrypted document key (EDEK) to a new tenant. Decrypts the EDEK then re-encrypts
// it to the new tenant. The DEK is then discarded. The old tenant and new tenant can be the same in order to re-key the
// document to the tenant's latest primary config.
func (r *TenantSecurityClient) RekeyEdek(ctx context.Context,
	edek *Edek,
	newTenantID string,
	metadata *RequestMetadata) (*Edek, error) {
	rekeyResp, err := r.tenantSecurityRequest.rekeyEdek(ctx, rekeyRequest{*edek, newTenantID, *metadata})
	if err != nil {
		return nil, err
	}
	return &rekeyResp.Edek, nil
}

// Send the provided security event to the TSP to be logged and analyzed. Note that logging a security event is an
// asynchronous operation at the TSP, so successful receipt of a security event does not mean
// that the event is deliverable or has been delivered to the tenant's logging system; it simply
// means that the event has been received and will be processed.
func (r *TenantSecurityClient) LogSecurityEvent(ctx context.Context,
	event SecurityEvent,
	metadata *EventMetadata) error {
	return r.tenantSecurityRequest.logSecurityEvent(ctx, &logSecurityEventRequest{event, *metadata})
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
