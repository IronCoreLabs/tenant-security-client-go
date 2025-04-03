package main

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"os"

	tsc "github.com/IronCoreLabs/tenant-security-client-go"
)

func main() {
	ctx := context.Background()
	tspAddress, _ := url.Parse("http://localhost:32804")
	// In order to communicate with the TSP, you need a matching API_KEY. Find the
	// right value from the end of the TSP configuration file, and set the API_KEY
	// environment variable to that value.
	apiKey := os.Getenv("API_KEY")
	if apiKey == "" {
		log.Fatal("Must set the API_KEY environment variable.")
	}

	// default to "tenant-gcp-l". Override by setting the TENANT_ID environment variable
	tenantID := os.Getenv("TENANT_ID")
	if tenantID == "" {
		tenantID = "tenant-gcp-l"
	}
	fmt.Printf("Using tenant %s\n", tenantID)

	tenantSecurityClient := tsc.NewTenantSecurityClient(apiKey, tspAddress, 0)

	// Create metadata used to associate this document to a tenant, name the document, and
	// identify the service or user making the call
	metadata := tsc.RequestMetadata{TenantID: tenantID,
		IclFields:    tsc.IclFields{RequestingID: "serviceOrUserId", DataLabel: "PII"},
		CustomFields: nil}

	cust1Record := tsc.PlaintextDocument{
		"id": []byte("19828392"),
	}
	cust2Record := tsc.PlaintextDocument{
		"id": []byte("12387643"),
	}
	documents := map[string]tsc.PlaintextDocument{"1": cust1Record, "2": cust2Record}

	// Encrypt the documents
	encryptionResults, err := tenantSecurityClient.BatchEncrypt(ctx, documents, &metadata)
	if err != nil {
		log.Fatalf("Failed to encrypt documents: %v", err)
	}

	encryptedDocuments := encryptionResults.Documents
	// Decrypt the documents
	decryptionResults, err := tenantSecurityClient.BatchDecrypt(ctx, encryptedDocuments, &metadata)
	if err != nil {
		log.Fatalf("Failed to decrypt documents: %v", err)
	}
	decryptedDocuments := decryptionResults.Documents

	decryptedFields1 := decryptedDocuments["1"].DecryptedFields
	decryptedID1 := string(decryptedFields1["id"])
	fmt.Printf("First decrypted ID: %s\n", decryptedID1)

	decryptedFields2 := decryptedDocuments["2"].DecryptedFields
	decryptedID2 := string(decryptedFields2["id"])
	fmt.Printf("Second decrypted ID: %s\n", decryptedID2)
}
