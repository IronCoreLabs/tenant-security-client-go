package tsc

import (
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

func TestMakeJsonRequest(t *testing.T) {
	apiKey := "fake_key"
	endpoint := wrapEndpoint

	handler := http.HandlerFunc(func(writer http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/1/document/wrap" {
			t.Errorf("request path %q", r.URL.Path)
		}
		authHeaders := r.Header["Authorization"]
		if len(authHeaders) != 1 {
			t.Fatalf("%d auth headers: %v", len(authHeaders), authHeaders)
		}
		authHeader := authHeaders[0]
		if authHeader != "cmk "+apiKey {
			t.Errorf("auth header %q", authHeader)
		}

		fmt.Fprintf(writer, "{}")
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	url, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	r := newTenantSecurityRequest(apiKey, url)
	reqBody := io.NopCloser(strings.NewReader(`{}`))
	respBody, err := r.doRequest(endpoint, reqBody)
	if err != nil {
		t.Errorf("read response body: %e", err)
	}
	if string(respBody) != "{}" {
		t.Errorf("response body: %q", respBody)
	}
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	if integrationTestTSC == nil {
		t.Skip("not doing integration tests")
	}

	document := PlaintextDocument{"foo": []byte("data")}
	metadata := RequestMetadata{TenantID: gcpTenantID, IclFields: IclFields{RequestingID: "foo", RequestID: "blah", SourceIP: "f", DataLabel: "sda", ObjectID: "ew"}, CustomFields: map[string]string{"f": "foo"}}
	encryptResult, err := integrationTestTSC.Encrypt(&document, &metadata)
	if err != nil {
		t.Fatal(err)
	}
	decryptResult, err := integrationTestTSC.Decrypt(encryptResult, &metadata)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, decryptResult.DecryptedFields, document)
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
	if err != nil {
		t.Fatal(err)
	}
	batchDecryptResult, err := integrationTestTSC.BatchDecrypt(batchEncryptResult.Documents, &metadata)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, len(batchDecryptResult.Documents), 2)
	assert.Equal(t, len(batchDecryptResult.Failures), 0)
	assert.Equal(t, batchDecryptResult.Documents["document1"].DecryptedFields, doc1)
	assert.Equal(t, batchDecryptResult.Documents["document2"].DecryptedFields, doc2)
}

func TestRekey(t *testing.T) {
	if integrationTestTSC == nil {
		t.Skip("not doing integration tests")
	}

	document := PlaintextDocument{"foo": []byte("data")}
	metadata := RequestMetadata{TenantID: azureTenantID, IclFields: IclFields{RequestingID: "foo", RequestID: "blah", SourceIP: "f", DataLabel: "sda", ObjectID: "ew"}, CustomFields: map[string]string{"f": "foo"}}
	encryptResult, err := integrationTestTSC.Encrypt(&document, &metadata)
	if err != nil {
		t.Fatal(err)
	}
	rekeyResult, err := integrationTestTSC.RekeyEdek(&encryptResult.Edek, gcpTenantID, &metadata)
	if err != nil {
		t.Fatal(err)
	}
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
