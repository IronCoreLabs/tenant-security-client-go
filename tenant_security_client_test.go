package tsc

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var integrationTestTSC *TenantSecurityClient
var err error

// These constants assume the TSP is running with decrypted `.env.integration` from this repo.
const (
	gcpTenantID   = "INTEGRATION-TEST-GCP"
	awsTenantID   = "INTEGRATION-TEST-AWS"
	azureTenantID = "INTEGRATION-TEST-AZURE"
)

func init() {
	apiKey := os.Getenv("API_KEY")
	if apiKey != "" {
		url, _ := url.Parse("http://localhost:7777/")
		integrationTestTSC, err = NewTenantSecurityClient(apiKey, url, WithAllowInsecure(true))
		if err != nil {
			log.Fatalf("Failed to create TSP: %v", err)
		}
	}
}

// The TSC keeps a limited number of tokens that allow workers to do CPU intensive tasks.
// This test makes sure we don't leak tokens.
func TestEncryptConcurrency(t *testing.T) {
	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, time.Second*30)
	defer cancel()

	url, err := url.Parse("https://localhost:1234")
	if err != nil {
		t.Fatal(err)
	}
	tsc, _ := NewTenantSecurityClient("unused", url, WithParallelism(2))

	tenantID := "unused tenant"
	mockDek := make([]byte, keyLen)
	// Fill the DEK using a cryptographically secure random number generator.
	_, err = io.ReadFull(rand.Reader, mockDek)
	if err != nil {
		t.Fatal(err)
	}

	// Generate a document to encrypt.
	numFields := 100
	fieldLen := 10
	origDoc := make(map[string][]byte)
	for i := 0; i < numFields; i++ {
		fieldName := fmt.Sprintf("field%d", i)
		var fieldData []byte
		for j := 0; j < fieldLen; j++ {
			fieldData = append(fieldData, byte(i%256))
		}
		origDoc[fieldName] = fieldData
	}

	encFields, err := tsc.encryptDocument(ctx, origDoc, tenantID, mockDek)
	if err != nil {
		t.Fatal(err)
	}

	decDoc, err := tsc.decryptDocument(ctx, encFields, mockDek)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, fmt.Sprint(origDoc), fmt.Sprint(decDoc))
}

func TestEncryptBadTenant(t *testing.T) {
	if integrationTestTSC == nil {
		t.Skip("not doing integration tests")
	}

	document := PlaintextDocument{"foo": []byte("data")}
	metadata := RequestMetadata{
		TenantID:     "not-a-tenant",
		IclFields:    IclFields{RequestingID: "foo", RequestID: "blah", SourceIP: "f", DataLabel: "sda", ObjectID: "ew"},
		CustomFields: map[string]string{"f": "foo"}}
	encryptResult, err := integrationTestTSC.Encrypt(context.Background(), document, &metadata)
	assert.Nil(t, encryptResult)
	assert.True(t, errors.Is(err, ErrUnknownTenantOrNoActiveKMSConfigurations))
	assert.ErrorContains(t, err, "No configurations available for the provided tenant")
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	if integrationTestTSC == nil {
		t.Skip("not doing integration tests")
	}

	ctx := context.Background()
	document := PlaintextDocument{"foo": []byte("data")}
	metadata := RequestMetadata{
		TenantID:     gcpTenantID,
		IclFields:    IclFields{RequestingID: "foo", RequestID: "blah", SourceIP: "f", DataLabel: "sda", ObjectID: "ew"},
		CustomFields: map[string]string{"f": "foo"}}
	encryptResult, err := integrationTestTSC.Encrypt(ctx, document, &metadata)
	assert.Nil(t, err)
	decryptResult, err := integrationTestTSC.Decrypt(ctx, encryptResult, &metadata)
	assert.Nil(t, err)
	assert.Equal(t, decryptResult.DecryptedFields, document)
}

func TestDoubleEncryptIntegration(t *testing.T) {
	if integrationTestTSC == nil {
		t.Skip("not doing integration tests")
	}

	ctx := context.Background()
	document := PlaintextDocument{"foo": []byte("data")}
	metadata := RequestMetadata{
		TenantID:     gcpTenantID,
		IclFields:    IclFields{RequestingID: "foo", RequestID: "blah", SourceIP: "f", DataLabel: "sda", ObjectID: "ew"},
		CustomFields: map[string]string{"f": "foo"}}
	encryptResult, err := integrationTestTSC.Encrypt(ctx, document, &metadata)
	assert.Nil(t, err)
	_, err2 := integrationTestTSC.Encrypt(ctx, encryptResult.EncryptedFields, &metadata)
	assert.ErrorIs(t, err2, ErrKindCrypto)
	assert.ErrorContains(t, err2, "already IronCore encrypted")
}

func TestEncryptWithExistingKey(t *testing.T) {
	if integrationTestTSC == nil {
		t.Skip("not doing integration tests")
	}

	ctx := context.Background()
	document := PlaintextDocument{"foo": []byte("data")}
	metadata := RequestMetadata{
		TenantID:     gcpTenantID,
		IclFields:    IclFields{RequestingID: "foo", RequestID: "blah", SourceIP: "f", DataLabel: "sda", ObjectID: "ew"},
		CustomFields: map[string]string{"f": "foo"}}
	encryptResult, err := integrationTestTSC.Encrypt(ctx, document, &metadata)
	assert.Nil(t, err)
	decryptResult, err := integrationTestTSC.Decrypt(ctx, encryptResult, &metadata)
	assert.Nil(t, err)
	assert.Equal(t, decryptResult.DecryptedFields, document)
	reEncryptResult, err := integrationTestTSC.EncryptWithExistingKey(ctx, decryptResult, &metadata)
	assert.Nil(t, err)
	reDecryptResult, err := integrationTestTSC.Decrypt(ctx, reEncryptResult, &metadata)
	assert.Nil(t, err)
	assert.Equal(t, reDecryptResult.DecryptedFields, document)
}

func TestBatchEncryptDecryptRoundtrip(t *testing.T) {
	if integrationTestTSC == nil {
		t.Skip("not doing integration tests")
	}

	ctx := context.Background()
	documents := make(map[string]PlaintextDocument)
	numDocs, numFields, fieldLen := 100, 100, 10
	for docNum := 0; docNum < numDocs; docNum++ {
		doc := make(map[string][]byte)
		for fieldNum := 0; fieldNum < numFields; fieldNum++ {
			fieldName := fmt.Sprintf("field%d", fieldNum)
			var fieldData []byte
			for byteNum := 0; byteNum < fieldLen; byteNum++ {
				fieldData = append(fieldData, byte(fieldNum%256))
			}
			doc[fieldName] = fieldData
		}
		docName := fmt.Sprintf("document %d", docNum)
		documents[docName] = doc
	}
	metadata := RequestMetadata{TenantID: gcpTenantID,
		IclFields:    IclFields{RequestingID: "foo", RequestID: "blah", SourceIP: "f", DataLabel: "sda", ObjectID: "ew"},
		CustomFields: map[string]string{"f": "foo"}}
	batchEncryptResult, err := integrationTestTSC.BatchEncrypt(ctx, documents, &metadata)
	assert.Nil(t, err)
	assert.Equal(t, "map[]", fmt.Sprint(batchEncryptResult.Failures))
	assert.Equal(t, len(batchEncryptResult.Documents), numDocs)
	batchDecryptResult, err := integrationTestTSC.BatchDecrypt(ctx, batchEncryptResult.Documents, &metadata)
	assert.Nil(t, err)
	assert.Equal(t, "map[]", fmt.Sprint(batchDecryptResult.Failures))
	assert.Equal(t, len(batchDecryptResult.Documents), numDocs)
}

func TestBatchDecryptPartialFailure(t *testing.T) {
	if integrationTestTSC == nil {
		t.Skip("not doing integration tests")
	}

	ctx := context.Background()
	doc := PlaintextDocument{"foo": []byte("data")}
	metadata := RequestMetadata{
		TenantID:     awsTenantID,
		IclFields:    IclFields{RequestingID: "foo", RequestID: "blah", SourceIP: "f", DataLabel: "sda", ObjectID: "ew"},
		CustomFields: map[string]string{"f": "foo"}}
	encryptedDoc, err := integrationTestTSC.Encrypt(ctx, doc, &metadata)
	assert.Nil(t, err)
	badEncryptedDoc := EncryptedDocument{map[string][]byte{"foo": []byte("bar")}, Base64Bytes{[]byte("edek")}}
	encryptedDocuments := map[string]EncryptedDocument{"good": *encryptedDoc, "bad": badEncryptedDoc}
	batchDecryptResult, err := integrationTestTSC.BatchDecrypt(ctx, encryptedDocuments, &metadata)
	assert.Nil(t, err)
	assert.Equal(t, len(batchDecryptResult.Documents), 1)
	assert.Equal(t, len(batchDecryptResult.Failures), 1)
	failure := batchDecryptResult.Failures["bad"]
	assert.True(t, errors.Is(failure, ErrInvalidProvidedEDEK))
	assert.ErrorContains(t, failure, "Provided EDEK didn't contain IronCore EDEKs")
}

func TestRekey(t *testing.T) {
	if integrationTestTSC == nil {
		t.Skip("not doing integration tests")
	}

	ctx := context.Background()
	document := PlaintextDocument{"foo": []byte("data")}
	metadata := RequestMetadata{
		TenantID:     azureTenantID,
		IclFields:    IclFields{RequestingID: "foo", RequestID: "blah", SourceIP: "f", DataLabel: "sda", ObjectID: "ew"},
		CustomFields: map[string]string{"f": "foo"}}
	encryptResult, err := integrationTestTSC.Encrypt(ctx, document, &metadata)
	assert.Nil(t, err)
	rekeyResult, err := integrationTestTSC.RekeyEdek(ctx, &encryptResult.Edek, gcpTenantID, &metadata)
	assert.Nil(t, err)
	newEncDoc := EncryptedDocument{encryptResult.EncryptedFields, *rekeyResult} // contains unchanged fields and new EDEK
	_, err = integrationTestTSC.Decrypt(ctx, &newEncDoc, &metadata)             // wrong tenant ID in metadata
	assert.ErrorContains(t, err, "is not assigned to tenant")
	metadata = RequestMetadata{TenantID: gcpTenantID, IclFields: IclFields{RequestingID: "foo"}}
	decryptResult, _ := integrationTestTSC.Decrypt(ctx, &newEncDoc, &metadata) // correct tenant ID in metadata
	assert.Equal(t, decryptResult.DecryptedFields, document)
}

func TestLogSecurityEvent(t *testing.T) {
	if integrationTestTSC == nil {
		t.Skip("not doing integration tests")
	}

	event := AdminAddEvent
	requestMetadata := RequestMetadata{
		TenantID:     azureTenantID,
		IclFields:    IclFields{RequestingID: "foo", RequestID: "blah", SourceIP: "f", DataLabel: "sda", ObjectID: "ew"},
		CustomFields: map[string]string{"f": "foo"}}
	eventMetadata := EventMetadata{time.Now(), requestMetadata}
	err := integrationTestTSC.LogSecurityEvent(context.Background(), event, &eventMetadata)
	assert.Nil(t, err)
}

func urlParseUnwrap(myURL string) *url.URL {
	parsed, _ := url.Parse(myURL)
	return parsed
}

func TestValidateTspAddress(t *testing.T) {
	assert.True(t, validateTspAddress(urlParseUnwrap("http://foo.com"), true))
	assert.False(t, validateTspAddress(urlParseUnwrap("http://foo.com"), false))
	assert.True(t, validateTspAddress(urlParseUnwrap("https://foo.com"), true))
	assert.True(t, validateTspAddress(urlParseUnwrap("https://foo.com"), false))
}
