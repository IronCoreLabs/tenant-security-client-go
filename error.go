package tsc

import "fmt"

type ErrorKind int

const (
	ErrorTspService ErrorKind = iota + 1
	ErrorSecurityEvent
	ErrorKMS
	ErrorCrypto
)

type ErrorCode int

const (
	unableToMakeRequest                      ErrorCode = 0
	unknownError                             ErrorCode = 100
	unauthorizedRequest                      ErrorCode = 101
	invalidRequestBody                       ErrorCode = 102
	noPrimaryKMSConfiguration                ErrorCode = 200
	unknownTenantOrNoActiveKMSConfigurations ErrorCode = 201
	kmsConfigurationDisabled                 ErrorCode = 202
	invalidProvidedEDEK                      ErrorCode = 203
	kmsWrapFailed                            ErrorCode = 204
	kmsUnwrapFailed                          ErrorCode = 205
	kmsAuthorizationFailed                   ErrorCode = 206
	kmsConfigurationInvalid                  ErrorCode = 207
	kmsUnreachable                           ErrorCode = 208
	securityEventRejected                    ErrorCode = 301
)

type TenantSecurityClientError struct {
	Kind    ErrorKind
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
}

func makeCryptoError(message string) TenantSecurityClientError {
	return TenantSecurityClientError{Kind: ErrorCrypto, Message: message}
}

func makeCodedError(code ErrorCode) TenantSecurityClientError {
	err := TenantSecurityClientError{Code: code}

	switch {
	case code < noPrimaryKMSConfiguration:
		err.Kind = ErrorTspService
	case code < securityEventRejected:
		err.Kind = ErrorKMS
	case code == securityEventRejected:
		err.Kind = ErrorSecurityEvent
	}

	switch code {
	// map to TspServiceException
	case unableToMakeRequest:
		err.Message = "Request to Tenant Security Proxy could not be made"
	case unknownError:
		err.Message = "Unknown request error occurred"
	case unauthorizedRequest:
		err.Message = "Request authorization header API key was incorrect."
	case invalidRequestBody:
		err.Message = "Request body was invalid."

	//map to KmsException
	case noPrimaryKMSConfiguration:
		err.Message = "Tenant has no primary KMS configuration."
	case unknownTenantOrNoActiveKMSConfigurations:
		err.Message = "Tenant either doesn't exist or has no active KMS configurations."
	case kmsConfigurationDisabled:
		err.Message = "Tenant configuration specified in EDEK is no longer active."
	case invalidProvidedEDEK:
		err.Message = "Provided EDEK was not valid."
	case kmsWrapFailed:
		err.Message = "Request to KMS API to wrap key returned invalid results."
	case kmsUnwrapFailed:
		err.Message = "Request to KMS API to unwrap key returned invalid results."
	case kmsAuthorizationFailed:
		err.Message = "Request to KMS failed because the tenant credentials were invalid or have been revoked."
	case kmsConfigurationInvalid:
		err.Message = "Request to KMS failed because the key configuration was invalid or the necessary permissions for the operation were missing/revoked."
	case kmsUnreachable:
		err.Message = "Request to KMS failed because KMS was unreachable."

	//map to SecurityEventException
	case securityEventRejected:
		err.Message = "Tenant Security Proxy could not accept the security event"
	}

	return err
}

func (r *TenantSecurityClientError) Error() string {
	return fmt.Sprintf("Code: %d. Message: %v", r.Code, r.Message)
}

func (e *TenantSecurityClientError) Is(target error) bool {
	t, ok := target.(*TenantSecurityClientError)
	if !ok {
		return false
	}
	return e.Kind == t.Kind && e.Code == t.Code
}
