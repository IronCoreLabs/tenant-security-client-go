package main

import (
	"fmt"
	"log"
	"net/url"

	tenant_security_client_go "github.com/IronCoreLabs/tenant-security-client-go"
)

func main() {
	url, err := url.Parse("http://localhost:32804/")

	cli, err := tenant_security_client_go.NewTenantSecurityClient("0WUaXesNgbTAuLwn", url)
	if err != nil {
		log.Fatalf("%e", err)
	}

	result, err := cli.Encrypt()
	if err != nil {
		log.Fatalf("%e", err)
	}

	fmt.Printf("Got %q from encrypt\n", result)
}
