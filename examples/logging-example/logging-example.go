package main

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"os"
	"time"

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

	tenantSecurityClient, err := tsc.NewTenantSecurityClient(apiKey, tspAddress, tsc.WithAllowInsecure(true))
	if err != nil {
		log.Fatalf("Failed to create TSP: %v", err)
	}

	// Example 1: logging a user-related event
	// Create metadata about the event. This example populates all possible fields with a value,
	// including the customFields map. Sets the timestamp to 5 seconds before the current data/time.

	customFields := map[string]string{"field1": "gumby", "field2": "gumby"}
	requestMetadata := tsc.RequestMetadata{TenantID: tenantID,
		IclFields: tsc.IclFields{RequestingID: "userId1",
			DataLabel: "PII",
			SourceIP:  "127.0.0.1",
			ObjectID:  "object1",
			RequestID: "Rq8675309"},
		CustomFields: customFields}
	metadata := tsc.EventMetadata{RequestMetadata: requestMetadata, TimestampMillis: time.Now().Add(-5 * time.Second)}

	err = tenantSecurityClient.LogSecurityEvent(ctx, tsc.UserLoginEvent, &metadata)
	if err != nil {
		log.Fatalf("Failed to log security event: %v", err)
	}
	fmt.Println("Successfully logged user login event.")

	// Example 2: logging an admin-related event
	// This example adds minimal metadata for the event. The timestamp should be roughly
	// 5 seconds after the one on the previous event.

	requestMetadata = tsc.RequestMetadata{TenantID: tenantID,
		IclFields:    tsc.IclFields{RequestingID: "userId1"},
		CustomFields: nil}
	metadata = tsc.EventMetadata{RequestMetadata: requestMetadata, TimestampMillis: time.Now()}

	err = tenantSecurityClient.LogSecurityEvent(ctx, tsc.AdminAddEvent, &metadata)
	if err != nil {
		log.Fatalf("Failed to log security event: %v", err)
	}
	fmt.Println("Successfully logged admin add event.")

	// You should be able to see that these two events were delivered in the TSP
	// logs. If you have access to the example tenant's SIEM, you can see these
	// events in their logs.
}
