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

	document := map[string][]byte{"foo": []byte("data")}
	metadata := tsc.RequestMetadata{TenantID: "tenant-gcp",
		IclFields:    tsc.IclFields{RequestingID: "foo", RequestID: "blah", SourceIP: "f", DataLabel: "sda", ObjectID: "ew"},
		CustomFields: map[string]string{"f": "foo"}}
	result, err := sdk.Encrypt(document, &metadata)
	if err != nil {
		log.Fatalf("%e", err)
	}
	decryptResult, err := sdk.Decrypt(result, &metadata)
	if err != nil {
		log.Fatalf("%e", err)
	}

	fmt.Println(decryptResult)
}
