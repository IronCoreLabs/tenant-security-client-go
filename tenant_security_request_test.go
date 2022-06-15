package tsc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var integrationTestTSC *TenantSecurityClient

// These constants assume the TSP is running with decrypted `.env.integration` from this repo.
const (
	gcpTenantID       = "INTEGRATION-TEST-DEV1-GCP"
	awsTenantID       = "INTEGRATION-TEST-DEV1-AWS"
	azureTenantID     = "INTEGRATION-TEST-DEV1-AZURE"
	leasedKeyTenantID = awsTenantID // TODO
)

func init() {
	apiKey := os.Getenv("API_KEY")
	if apiKey != "" {
		url, _ := url.Parse("http://localhost:7777/")
		integrationTestTSC = NewTenantSecurityClient(apiKey, url, 0)
	}
}

func TestMakeJsonRequest(t *testing.T) {
	apiKey := "fake_key"
	endpoint := wrapEndpoint
	handler := http.HandlerFunc(func(writer http.ResponseWriter, r *http.Request) {
		assert.Equal(t, r.URL.Path, "/api/1/document/wrap")
		authHeaders := r.Header["Authorization"]
		assert.Equal(t, len(authHeaders), 1)
		authHeader := authHeaders[0]
		assert.Equal(t, authHeader, "cmk "+apiKey)
		fmt.Fprintf(writer, "{}")
	})
	server := httptest.NewServer(handler)
	defer server.Close()
	url, err := url.Parse(server.URL)
	assert.Nil(t, err)
	r := newTenantSecurityRequest(apiKey, url)
	reqBody := io.NopCloser(strings.NewReader(`{}`))
	respBody, err := r.doRequest(context.Background(), endpoint, reqBody)
	assert.Nil(t, err)
	assert.Equal(t, string(respBody), "{}")
}

func TestEncryptBadTenant(t *testing.T) {
	if integrationTestTSC == nil {
		t.Skip("not doing integration tests")
	}

	document := PlaintextDocument{"foo": []byte("data")}
	metadata := RequestMetadata{TenantID: "not-a-tenant", IclFields: IclFields{RequestingID: "foo", RequestID: "blah", SourceIP: "f", DataLabel: "sda", ObjectID: "ew"}, CustomFields: map[string]string{"f": "foo"}}
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
	metadata := RequestMetadata{TenantID: gcpTenantID, IclFields: IclFields{RequestingID: "foo", RequestID: "blah", SourceIP: "f", DataLabel: "sda", ObjectID: "ew"}, CustomFields: map[string]string{"f": "foo"}}
	encryptResult, err := integrationTestTSC.Encrypt(ctx, document, &metadata)
	assert.Nil(t, err)
	decryptResult, err := integrationTestTSC.Decrypt(ctx, encryptResult, &metadata)
	assert.Nil(t, err)
	assert.Equal(t, decryptResult.DecryptedFields, document)
}

func TestBatchEncryptDecryptRoundtrip(t *testing.T) {
	if integrationTestTSC == nil {
		t.Skip("not doing integration tests")
	}

	ctx := context.Background()
	documents := make(map[string]PlaintextDocument)
	numDocs, numFields, fieldLen := 1000, 100, 10
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
	metadata := RequestMetadata{TenantID: leasedKeyTenantID, IclFields: IclFields{RequestingID: "foo", RequestID: "blah", SourceIP: "f", DataLabel: "sda", ObjectID: "ew"}, CustomFields: map[string]string{"f": "foo"}}
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
	metadata := RequestMetadata{TenantID: awsTenantID, IclFields: IclFields{RequestingID: "foo", RequestID: "blah", SourceIP: "f", DataLabel: "sda", ObjectID: "ew"}, CustomFields: map[string]string{"f": "foo"}}
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
	metadata := RequestMetadata{TenantID: azureTenantID, IclFields: IclFields{RequestingID: "foo", RequestID: "blah", SourceIP: "f", DataLabel: "sda", ObjectID: "ew"}, CustomFields: map[string]string{"f": "foo"}}
	encryptResult, err := integrationTestTSC.Encrypt(ctx, document, &metadata)
	assert.Nil(t, err)
	rekeyResult, err := integrationTestTSC.RekeyEdek(ctx, &encryptResult.Edek, gcpTenantID, &metadata)
	assert.Nil(t, err)
	newEncryptedDocument := EncryptedDocument{encryptResult.EncryptedFields, *rekeyResult} // contains unchanged fields and new EDEK
	_, err = integrationTestTSC.Decrypt(ctx, &newEncryptedDocument, &metadata)             // wrong tenant ID in metadata
	assert.ErrorContains(t, err, "The KMS config used to encrypt this DEK is no longer accessible")
	metadata = RequestMetadata{TenantID: gcpTenantID, IclFields: IclFields{RequestingID: "foo"}}
	decryptResult, _ := integrationTestTSC.Decrypt(ctx, &newEncryptedDocument, &metadata) // correct tenant ID in metadata
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
	err := integrationTestTSC.LogSecurityEvent(context.Background(), event, &eventMetadata)
	assert.Nil(t, err)
}
