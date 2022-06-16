//nolint: forbidigo
package main

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"os"

	tsc "github.com/IronCoreLabs/tenant-security-client-go"
)

//nolint: funlen
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

	//
	// Example 1: encrypting/decrypting a customer record
	//

	// Create metadata used to associate this document to a tenant and identify the service or user making the call
	metadata := tsc.RequestMetadata{TenantID: tenantID,
		IclFields:    tsc.IclFields{RequestingID: "serviceOrUserId", DataLabel: "PII"},
		CustomFields: nil}

	// Create a map containing your data
	custRecord := tsc.PlaintextDocument{
		"ssn":     []byte("000-12-2345"),
		"address": []byte("2825-519 Stone Creek Rd, Bozeman, MT 59715"),
		"name":    []byte("Jim Bridger"),
	}

	encryptedResults, err := tenantSecurityClient.Encrypt(ctx, custRecord, &metadata)
	if err != nil {
		log.Fatalf("Failed to encrypt document: %v", err)
	}
	// persist the EDEK and encryptedDocument to your persistence layer
	edek := encryptedResults.Edek
	encryptedDocument := encryptedResults.EncryptedFields

	// later, retrieve the EDEK and encryptedDocument from your persistence layer
	retrievedEncryptedDocument := tsc.EncryptedDocument{EncryptedFields: encryptedDocument, Edek: edek}

	decryptedPlaintext, err := tenantSecurityClient.Decrypt(ctx, &retrievedEncryptedDocument, &metadata)
	if err != nil {
		log.Fatalf("Failed to decrypt document: %v", err)
	}
	decryptedValues := decryptedPlaintext.DecryptedFields

	fmt.Printf("Decrypted SSN: %s\n", decryptedValues["ssn"])
	fmt.Printf("Decrypted address: %s\n", decryptedValues["address"])
	fmt.Printf("Decrypted name: %s\n", decryptedValues["name"])

	//
	// Example 2: encrypting/decrypting a file, using the filesystem for persistence
	//

	sourceFilename := "success.jpg"
	toEncryptBytes, err := os.ReadFile(sourceFilename)
	if err != nil {
		log.Fatalf("Failed to read file: %v", err)
	}
	toEncrypt := tsc.PlaintextDocument{"file": toEncryptBytes}
	// Encrypt the file.
	encryptedResults, err = tenantSecurityClient.Encrypt(ctx, toEncrypt, &metadata)
	if err != nil {
		log.Fatalf("Failed to encrypt document: %v", err)
	}

	encryptedFileName := sourceFilename + ".enc"
	encryptedDekName := sourceFilename + ".edek"
	// write the encrypted file and the encrypted key to the filesystem
	err = os.WriteFile(encryptedFileName, encryptedResults.EncryptedFields["file"], 0600)
	if err != nil {
		log.Fatalf("Failed to write file: %v", err)
	}
	fmt.Printf("Wrote encrypted file to %s\n", encryptedFileName)
	err = os.WriteFile(encryptedDekName, encryptedResults.Edek.Bytes, 0600)
	if err != nil {
		log.Fatalf("Failed to write file: %v", err)
	}
	fmt.Printf("Wrote edek to %s\n", encryptedDekName)

	// some time later... read the file from the disk
	encryptedBytes, err := os.ReadFile(encryptedFileName)
	if err != nil {
		log.Fatalf("Failed to read file: %v", err)
	}
	encryptedDek, err := os.ReadFile(encryptedDekName)
	if err != nil {
		log.Fatalf("Failed to read file: %v", err)
	}

	fileAndEdek := tsc.EncryptedDocument{EncryptedFields: tsc.PlaintextDocument{"file": encryptedBytes},
		Edek: tsc.Edek{Bytes: encryptedDek}}

	// decrypt
	roundtripFile, err := tenantSecurityClient.Decrypt(ctx, &fileAndEdek, &metadata)
	if err != nil {
		log.Fatalf("Failed to decrypt file: %v", err)
	}

	// write the decrypted file back to the filesystem
	err = os.WriteFile("decrypted.jpg", roundtripFile.DecryptedFields["file"], 0600)
	if err != nil {
		log.Fatalf("Failed to write file: %v", err)
	}

	fmt.Println("Wrote decrypted file to decrypted.jpg")

}
