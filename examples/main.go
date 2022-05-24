package main

import (
	"fmt"
	"log"
	"net/url"

	tenant_security_client_go "github.com/IronCoreLabs/tenant-security-client-go"
)

func main() {
	url, err := url.Parse("http://localhost:32804/")
	if err != nil {
		log.Fatalf("%e", err)
	}

	cli, err := tenant_security_client_go.NewTenantSecurityClient("0WUaXesNgbTAuLwn", url)
	if err != nil {
		log.Fatalf("%e", err)
	}

	document := map[string][]byte{"foo": []byte("data")}
	metadata := tenant_security_client_go.RequestMetadata{TenantId: "tenant-gc", IclFields: tenant_security_client_go.IclFields{RequestingId: "foo", RequestId: "blah", SourceIp: "f", DataLabel: "sda", ObjectId: "ew"}, CustomFields: map[string]string{"f": "foo"}}
	result, err := cli.Encrypt(document, metadata)
	if err != nil {
		log.Fatalf("%e", err)
	}

	fmt.Println(result)
}
