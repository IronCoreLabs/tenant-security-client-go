package tenant_security_client_go

import (
	"net/url"

	"github.com/IronCoreLabs/tenant-security-client-go/proto"
)

type TenantSecurityClient struct {
	tenantSecurityRequest tenantSecurityRequest
}

func NewTenantSecurityClient(apiKey string, tspAddress *url.URL) (*TenantSecurityClient, error) {
	req, err := newTenantSecurityRequest(apiKey, tspAddress)
	if err != nil {
		return nil, err
	}

	client := TenantSecurityClient{tenantSecurityRequest: *req}
	return &client, nil
}

func (r *TenantSecurityClient) Encrypt() (string, error) {
	var _ proto.DataControlPlatformHeader
	return r.tenantSecurityRequest.wrapKey()
}

//go:generate protoc --go_out=. document_header.proto
