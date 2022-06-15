package main

import (
	"context"
	"log"
	"net/url"

	tsc "github.com/IronCoreLabs/tenant-security-client-go"
)

func main() {
	ctx := context.Background()

	url, err := url.Parse("http://localhost:32804/")
	if err != nil {
		log.Fatalf("%v", err)
	}

	sdk := tsc.NewTenantSecurityClient("0WUaXesNgbTAuLwn", url, 0)
	if err != nil {
		log.Fatalf("%v", err)
	}

	documents := map[string]tsc.PlaintextDocument{"document1": {"foo": []byte("data")}, "document2": {"bar": {1, 2, 3, 4}}}
	metadata := tsc.RequestMetadata{TenantID: "tenant-gcp", IclFields: tsc.IclFields{RequestingID: "foo", RequestID: "blah", SourceIP: "f", DataLabel: "sda", ObjectID: "ew"}, CustomFields: map[string]string{"f": "foo"}}
	result, err := sdk.BatchEncrypt(ctx, documents, &metadata)
	if err != nil {
		log.Fatalf("%v", err)
	}
	decryptResult, err := sdk.BatchDecrypt(ctx, result.Documents, &metadata)
	if err != nil {
		log.Fatalf("%v", err)
	}

	log.Printf("%+v\n", decryptResult)
}
