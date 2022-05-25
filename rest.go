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
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	bytes, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return err
	}
	b.s = string(bytes)
	return nil
}

type Dek = Base64String
type Edek = Base64String
