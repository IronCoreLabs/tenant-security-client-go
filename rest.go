package tenant_security_client_go

import (
	"encoding/base64"
	"encoding/json"
)

type WrapKeyResponse struct {
	Dek  Dek  `json:"dek"`
	Edek Edek `json:"edek"`
}

type Base64String struct {
	s string
}

func (b *Base64String) UnmarshalJSON(data []byte) error {
	var v string
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	foo, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return err
	}
	b.s = string(foo)
	return nil
}

type Dek = Base64String
type Edek = Base64String
