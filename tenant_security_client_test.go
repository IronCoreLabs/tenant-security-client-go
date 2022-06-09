package tsc

import (
	"errors"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var integrationTestTSC *TenantSecurityClient

// These constants assume the TSP is running with decrypted `.env.integration` from this repo.
const (
	gcpTenantID   = "INTEGRATION-TEST-DEV1-GCP"
	awsTenantID   = "INTEGRATION-TEST-DEV1-AWS"
	azureTenantID = "INTEGRATION-TEST-DEV1-AZURE"
)

func init() {
	apiKey := os.Getenv("API_KEY")
	if apiKey != "" {
		url, _ := url.Parse("http://localhost:7777/")
		integrationTestTSC = NewTenantSecurityClient(apiKey, url)
	}
}

func TestEncryptBadTenant(t *testing.T) {
	if integrationTestTSC == nil {
		t.Skip("not doing integration tests")
	}

	document := PlaintextDocument{"foo": []byte("data")}
	metadata := RequestMetadata{TenantID: "not-a-tenant", IclFields: IclFields{RequestingID: "foo", RequestID: "blah", SourceIP: "f", DataLabel: "sda", ObjectID: "ew"}, CustomFields: map[string]string{"f": "foo"}}
	encryptResult, err := integrationTestTSC.Encrypt(&document, &metadata)
	assert.Nil(t, encryptResult)
	assert.True(t, errors.Is(err, ErrUnknownTenantOrNoActiveKMSConfigurations))
	assert.ErrorContains(t, err, "No configurations available for the provided tenant")

}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	if integrationTestTSC == nil {
		t.Skip("not doing integration tests")
	}

	document := PlaintextDocument{"foo": []byte("data")}
	metadata := RequestMetadata{TenantID: gcpTenantID, IclFields: IclFields{RequestingID: "foo", RequestID: "blah", SourceIP: "f", DataLabel: "sda", ObjectID: "ew"}, CustomFields: map[string]string{"f": "foo"}}
	encryptResult, err := integrationTestTSC.Encrypt(&document, &metadata)
	assert.Nil(t, err)
	decryptResult, err := integrationTestTSC.Decrypt(encryptResult, &metadata)
	assert.Nil(t, err)
	assert.Equal(t, decryptResult.DecryptedFields, document)
}

func TestEncryptWithExistingKey(t *testing.T) {
	if integrationTestTSC == nil {
		t.Skip("not doing integration tests")
	}

	document := PlaintextDocument{"foo": []byte("data")}
	metadata := RequestMetadata{TenantID: gcpTenantID, IclFields: IclFields{RequestingID: "foo", RequestID: "blah", SourceIP: "f", DataLabel: "sda", ObjectID: "ew"}, CustomFields: map[string]string{"f": "foo"}}
	encryptResult, err := integrationTestTSC.Encrypt(&document, &metadata)
	assert.Nil(t, err)
	decryptResult, err := integrationTestTSC.Decrypt(encryptResult, &metadata)
	assert.Nil(t, err)
	assert.Equal(t, decryptResult.DecryptedFields, document)
	reEncryptResult, err := integrationTestTSC.EncryptWithExistingKey(decryptResult, &metadata)
	assert.Nil(t, err)
	reDecryptResult, err := integrationTestTSC.Decrypt(reEncryptResult, &metadata)
	assert.Nil(t, err)
	assert.Equal(t, reDecryptResult.DecryptedFields, document)
}

func TestBatchEncryptDecryptRoundtrip(t *testing.T) {
	if integrationTestTSC == nil {
		t.Skip("not doing integration tests")
	}

	doc1 := PlaintextDocument{"foo": []byte("data")}
	doc2 := PlaintextDocument{"bar": {1, 2, 3, 4}}
	documents := map[string]PlaintextDocument{"document1": doc1, "document2": doc2}
	metadata := RequestMetadata{TenantID: awsTenantID, IclFields: IclFields{RequestingID: "foo", RequestID: "blah", SourceIP: "f", DataLabel: "sda", ObjectID: "ew"}, CustomFields: map[string]string{"f": "foo"}}
	batchEncryptResult, err := integrationTestTSC.BatchEncrypt(documents, &metadata)
	assert.Nil(t, err)
	batchDecryptResult, err := integrationTestTSC.BatchDecrypt(batchEncryptResult.Documents, &metadata)
	assert.Nil(t, err)
	assert.Equal(t, len(batchDecryptResult.Documents), 2)
	assert.Equal(t, len(batchDecryptResult.Failures), 0)
	assert.Equal(t, batchDecryptResult.Documents["document1"].DecryptedFields, doc1)
	assert.Equal(t, batchDecryptResult.Documents["document2"].DecryptedFields, doc2)
}

func TestBatchDecryptPartialFailure(t *testing.T) {
	if integrationTestTSC == nil {
		t.Skip("not doing integration tests")
	}

	doc := PlaintextDocument{"foo": []byte("data")}
	metadata := RequestMetadata{TenantID: awsTenantID, IclFields: IclFields{RequestingID: "foo", RequestID: "blah", SourceIP: "f", DataLabel: "sda", ObjectID: "ew"}, CustomFields: map[string]string{"f": "foo"}}
	encryptedDoc, err := integrationTestTSC.Encrypt(&doc, &metadata)
	assert.Nil(t, err)
	badEncryptedDoc := EncryptedDocument{map[string][]byte{"foo": []byte("bar")}, Base64Bytes{[]byte("edek")}}
	encryptedDocuments := map[string]EncryptedDocument{"good": *encryptedDoc, "bad": badEncryptedDoc}
	batchDecryptResult, err := integrationTestTSC.BatchDecrypt(encryptedDocuments, &metadata)
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

	document := PlaintextDocument{"foo": []byte("data")}
	metadata := RequestMetadata{TenantID: azureTenantID, IclFields: IclFields{RequestingID: "foo", RequestID: "blah", SourceIP: "f", DataLabel: "sda", ObjectID: "ew"}, CustomFields: map[string]string{"f": "foo"}}
	encryptResult, err := integrationTestTSC.Encrypt(&document, &metadata)
	assert.Nil(t, err)
	rekeyResult, err := integrationTestTSC.RekeyEdek(&encryptResult.Edek, gcpTenantID, &metadata)
	assert.Nil(t, err)
	newEncryptedDocument := EncryptedDocument{encryptResult.EncryptedFields, *rekeyResult} // contains unchanged fields and new EDEK
	_, err = integrationTestTSC.Decrypt(&newEncryptedDocument, &metadata)                  // wrong tenant ID in metadata
	assert.ErrorContains(t, err, "The KMS config used to encrypt this DEK is no longer accessible")
	metadata = RequestMetadata{TenantID: gcpTenantID, IclFields: IclFields{RequestingID: "foo"}}
	decryptResult, _ := integrationTestTSC.Decrypt(&newEncryptedDocument, &metadata) // correct tenant ID in metadata
	assert.Equal(t, decryptResult.DecryptedFields, document)
}

func TestLogSecurityEvent(t *testing.T) {
	if integrationTestTSC == nil {
		t.Skip("not doing integration tests")
	}

	event := AdminAddEvent
	timestamp := int(time.Now().UnixMilli())
	requestMetadata := RequestMetadata{TenantID: azureTenantID, IclFields: IclFields{RequestingID: "foo", RequestID: "blah", SourceIP: "f", DataLabel: "sda", ObjectID: "ew"}, CustomFields: map[string]string{"f": "foo"}}
	eventMetadata := EventMetadata{&timestamp, requestMetadata}
	err := integrationTestTSC.LogSecurityEvent(event, &eventMetadata)
	assert.Nil(t, err)
}
