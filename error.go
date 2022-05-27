package tsc

import "fmt"

type TenantSecurityClientError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (r *TenantSecurityClientError) Error() string {
	return fmt.Sprintf("Code: %d. Message: %v", r.Code, r.Message)
}
