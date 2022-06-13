//nolint: forbidigo
package main

import (
	"fmt"
	"log"
	"net/url"
	"os"

	tsc "github.com/IronCoreLabs/tenant-security-client-go"
)

//nolint: funlen
func main() {
	tspAddress, _ := url.Parse("http://localhost:32804")
	// In order to communicate with the TSP, you need a matching API_KEY. Find the
	// right value from the end of the TSP configuration file, and set the API_KEY
	// environment variable to that value.
	apiKey := os.Getenv("API_KEY")
	if apiKey == "" {
		log.Fatal("Must set the API_KEY environment variable.")
	}

	tenantSecurityClient := tsc.NewTenantSecurityClient(apiKey, tspAddress)

	startingTenant := "tenant-gcp"

	// Create metadata used to associate this document to a GCP tenant, name the document, and
	// identify the service or user making the call
	metadata := tsc.RequestMetadata{TenantID: startingTenant, IclFields: tsc.IclFields{RequestingID: "serviceOrUserId", DataLabel: "PII"}, CustomFields: nil}

	//
	// Part 1: Encrypt a file for the GCP tenant, using the filesystem for persistence
	//

	sourceFilename := "success.jpg"
	toEncryptBytes, err := os.ReadFile(sourceFilename)
	if err != nil {
		log.Fatalf("Failed to read file: %v", err)
	}
	toEncrypt := tsc.PlaintextDocument{"file": toEncryptBytes}
	// Encrypt the file to the GCP tenant
	encryptedResults, err := tenantSecurityClient.Encrypt(&toEncrypt, &metadata)
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
	fmt.Printf("Wrote EDEK to %s\n", encryptedDekName)

	//
	// Part 2: Re-key the EDEK to the AWS tenant
	//

	// Some time later... read the EDEK from the disk (don't need the encrypted file)
	newTenant := "tenant-aws"
	encryptedDek, err := os.ReadFile(encryptedDekName)
	if err != nil {
		log.Fatalf("Failed to read file: %v", err)
	}

	// Re-key the EDEK to the AWS tenant
	newEdek, err := tenantSecurityClient.RekeyEdek(&tsc.Edek{Bytes: encryptedDek}, newTenant, &metadata)
	if err != nil {
		log.Fatalf("Failed to rekey EDEK: %v", err)
	}
	fmt.Println("Rekeyed EDEK to tenant-aws")

	// Replace the stored EDEK with the newly re-keyed one
	err = os.WriteFile(encryptedDekName, newEdek.Bytes, 0600)
	if err != nil {
		log.Fatalf("Failed to write file: %v", err)
	}
	fmt.Printf("Wrote tenant-aws EDEK to %s\n", encryptedDekName)

	//
	// Part 3: Decrypt the document for the AWS tenant
	//

	// Some time later... read the file from the disk
	encryptedBytes, err := os.ReadFile(encryptedFileName)
	if err != nil {
		log.Fatalf("Failed to read file: %v", err)
	}
	encryptedDek, err = os.ReadFile(encryptedDekName)
	if err != nil {
		log.Fatalf("Failed to read file: %v", err)
	}

	fileAndEdek := tsc.EncryptedDocument{EncryptedFields: map[string][]byte{"file": encryptedBytes}, Edek: tsc.Edek{Bytes: encryptedDek}}
	newMetadata := tsc.RequestMetadata{TenantID: newTenant, IclFields: tsc.IclFields{RequestingID: "serviceOrUserId", DataLabel: "PII"}, CustomFields: nil}

	// Decrypt for AWS tenant
	roundtripFile, err := tenantSecurityClient.Decrypt(&fileAndEdek, &newMetadata)
	if err != nil {
		log.Fatalf("Failed to decrypt document: %v", err)
	}
	fmt.Println("Decrypted file for tenant-aws")

	// Write the decrypted file back to the filesystem
	err = os.WriteFile("decrypted.jpg", roundtripFile.DecryptedFields["file"], 0600)
	if err != nil {
		log.Fatalf("Failed to write file: %v", err)
	}
	fmt.Println("Wrote decrypted file to decrypted.jpg")
}
