package tsc

import (
	"errors"
	"fmt"
)

type ErrorKind int

const (
	ErrorTSPService ErrorKind = iota + 1
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
	Kind    ErrorKind `json:"-"`
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
	wrapped error     `json:"-"`
}

func makeCryptoErrorf(format string, a ...interface{}) *TenantSecurityClientError {
	//nolint:goerr113
	message := fmt.Errorf(format, a...)
	return &TenantSecurityClientError{Kind: ErrorCrypto, Message: message.Error(), wrapped: errors.Unwrap(message)}
}

func makeCodedError(code ErrorCode, wrapped error) *TenantSecurityClientError {
	err := TenantSecurityClientError{Code: code, wrapped: wrapped}

	switch {
	case code < noPrimaryKMSConfiguration:
		err.Kind = ErrorTSPService
	case code < securityEventRejected:
		err.Kind = ErrorKMS
	case code == securityEventRejected:
		err.Kind = ErrorSecurityEvent
	}

	switch code {
	// These are all ErrorTSPService.
	case unableToMakeRequest:
		err.Message = "request to Tenant Security Proxy could not be made"
	case unknownError:
		err.Message = "unknown request error occurred"
	case unauthorizedRequest:
		err.Message = "request authorization header API key was incorrect"
	case invalidRequestBody:
		err.Message = "request body was invalid"

	// These are all ErrorKMS.
	case noPrimaryKMSConfiguration:
		err.Message = "tenant has no primary KMS configuration"
	case unknownTenantOrNoActiveKMSConfigurations:
		err.Message = "tenant either doesn't exist or has no active KMS configurations"
	case kmsConfigurationDisabled:
		err.Message = "tenant configuration specified in EDEK is no longer active"
	case invalidProvidedEDEK:
		err.Message = "provided EDEK was not valid"
	case kmsWrapFailed:
		err.Message = "request to KMS API to wrap key returned invalid results"
	case kmsUnwrapFailed:
		err.Message = "request to KMS API to unwrap key returned invalid results"
	case kmsAuthorizationFailed:
		err.Message = "request to KMS failed because the tenant credentials were invalid or have been revoked"
	case kmsConfigurationInvalid:
		err.Message = "request to KMS failed because the key configuration was invalid or the necessary permissions for the operation were missing/revoked"
	case kmsUnreachable:
		err.Message = "request to KMS failed because KMS was unreachable"

	// This is ErrorSecurityEvent.
	case securityEventRejected:
		err.Message = "tenant Security Proxy could not accept the security event"
	}

	return &err
}

func (e *TenantSecurityClientError) Error() string {
	return fmt.Sprintf("Code: %d. Message: %v", e.Code, e.Message)
}

func (e *TenantSecurityClientError) Is(target error) bool {
	//nolint:errorlint
	t, ok := target.(*TenantSecurityClientError)
	if !ok {
		return false
	}
	return e.Kind == t.Kind && e.Code == t.Code
}

func (e *TenantSecurityClientError) Unwrap() error {
	return e.wrapped
}
