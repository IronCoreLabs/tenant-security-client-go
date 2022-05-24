package tenant_security_client_go

import (
	"net/url"

	"github.com/IronCoreLabs/tenant-security-client-go/crypto"
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

func (r *TenantSecurityClient) Encrypt(document PlaintextDocument, metadata RequestMetadata) (map[string][]byte, error) {
	wrapKeyResp, err := r.tenantSecurityRequest.wrapKey(metadata)
	if err != nil {
		return nil, err
	}
	encrypted := make(map[string][]byte, len(document))
	for k, v := range document {
		encrypted[k], err = crypto.EncryptDocument(v, metadata.TenantId, []byte(wrapKeyResp.Dek.s))
		if err != nil { // TODO: bad to just exit like this
			return nil, err
		}
	}
	return encrypted, nil
}

type PlaintextDocument = map[string][]byte

type RequestMetadata struct {
	TenantId     string            `json:"tenantId"`
	IclFields    IclFields         `json:"iclFields"`
	CustomFields map[string]string `json:"customFields"`
}

type IclFields struct {
	RequestingId string `json:"requestingId"`
	DataLabel    string `json:"dataLabel,omitempty"`
	SourceIp     string `json:"sourceIp,omitempty"`
	ObjectId     string `json:"objectId,omitempty"`
	RequestId    string `json:"requestId,omitempty"`
}

//go:generate protoc --go_out=. document_header.proto
