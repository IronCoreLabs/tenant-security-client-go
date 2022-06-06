package main

import (
	"fmt"
	"log"
	"net/url"

	tsc "github.com/IronCoreLabs/tenant-security-client-go"
)

func main() {
	url, err := url.Parse("http://localhost:32804/")
	if err != nil {
		log.Fatalf("%e", err)
	}

	sdk := tsc.NewTenantSecurityClient("0WUaXesNgbTAuLwn", url)
	if err != nil {
		log.Fatalf("%e", err)
	}

	documents := map[string]tsc.PlaintextDocument{"document1": {"foo": []byte("data")}, "document2": {"bar": {1, 2, 3, 4}}}
	metadata := tsc.RequestMetadata{TenantID: "tenant-gcp", IclFields: tsc.IclFields{RequestingID: "foo", RequestID: "blah", SourceIP: "f", DataLabel: "sda", ObjectID: "ew"}, CustomFields: map[string]string{"f": "foo"}}
	result, err := sdk.BatchEncrypt(documents, &metadata)
	if err != nil {
		log.Fatalf("%e", err)
	}
	decryptResult, err := sdk.BatchDecrypt(result.Documents, &metadata)
	if err != nil {
		log.Fatalf("%e", err)
	}

	fmt.Printf("%+v\n", decryptResult)
}
