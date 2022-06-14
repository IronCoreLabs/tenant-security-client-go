package tsc

import (
	"encoding/json"
	"errors"
	"fmt"
)

type ErrorKind int
type ErrorCode int

const (
	errorKindUnknown ErrorKind = iota
	errorKindTSPService
	errorKindSecurityEvent
	errorKindKMS
	errorKindCrypto
	errorKindNetwork
	errorKindLocal
)

/**
 * These are kinds of errors. Use errors.Is to see if a specific error is of this kind.
 */
var (
	ErrKindUnknown       = &Error{Kind: errorKindUnknown}
	ErrKindTSPService    = &Error{Kind: errorKindTSPService}
	ErrKindSecurityEvent = &Error{Kind: errorKindSecurityEvent}
	ErrKindKMS           = &Error{Kind: errorKindKMS}
	ErrKindCrypto        = &Error{Kind: errorKindCrypto}
	ErrKindNetwork       = &Error{Kind: errorKindNetwork}
	ErrKindLocal         = &Error{Kind: errorKindLocal}
)

/**
 * These are specific coded errors that can be received from the TSP. Use errors.Is to compare
 * against them.
 */
//nolint:gomnd
var (
	ErrUnknownError                             = &Error{Kind: errorKindTSPService, Code: 100}
	ErrUnauthorizedRequest                      = &Error{Kind: errorKindTSPService, Code: 101}
	ErrInvalidRequestBody                       = &Error{Kind: errorKindTSPService, Code: 102}
	ErrNoPrimaryKMSConfiguration                = &Error{Kind: errorKindKMS, Code: 200}
	ErrUnknownTenantOrNoActiveKMSConfigurations = &Error{Kind: errorKindKMS, Code: 201}
	ErrKmsConfigurationDisabled                 = &Error{Kind: errorKindKMS, Code: 202}
	ErrInvalidProvidedEDEK                      = &Error{Kind: errorKindKMS, Code: 203}
	ErrKmsWrapFailed                            = &Error{Kind: errorKindKMS, Code: 204}
	ErrKmsUnwrapFailed                          = &Error{Kind: errorKindKMS, Code: 205}
	ErrKmsAuthorizationFailed                   = &Error{Kind: errorKindKMS, Code: 206}
	ErrKmsConfigurationInvalid                  = &Error{Kind: errorKindKMS, Code: 207}
	ErrKmsUnreachable                           = &Error{Kind: errorKindKMS, Code: 208}
	ErrSecurityEventRejected                    = &Error{Kind: errorKindSecurityEvent, Code: 301}
)

type Error struct {
	Kind    ErrorKind
	Code    ErrorCode
	Message string
	wrapped error
}

func makeErrorf(kind ErrorKind, format string, a ...interface{}) *Error {
	//nolint:goerr113
	err := fmt.Errorf(format, a...)
	message := err.Error()
	wrapped := errors.Unwrap(err)
	return &Error{Kind: kind, Message: message, wrapped: wrapped}
}

/**
 * setErrorKind is a helper function used when we read the error code from the remote TSP.
 * We want to set the error kind from the code, so the user knows how to handle the error.
 */
func (e *Error) setErrorKind() {
	switch {
	case e.Code < ErrNoPrimaryKMSConfiguration.Code:
		e.Kind = ErrKindTSPService.Kind
	case e.Code < ErrSecurityEventRejected.Code:
		e.Kind = ErrKindKMS.Kind
	case e.Code == ErrSecurityEventRejected.Code:
		e.Kind = ErrKindSecurityEvent.Kind
	}
}

func (e *Error) Error() string {
	if e.Code == 0 {
		return e.Message
	}

	return fmt.Sprintf("(code: %d) %v", e.Code, e.Message)
}

func (e *Error) Is(target error) bool {
	//nolint:errorlint
	t, ok := target.(*Error)
	if !ok {
		return false
	}
	return e.Kind == t.Kind && (t.Code == 0 || e.Code == t.Code)
}

//nolint:wrapcheck // Because this function is called by json code, it should return a json error.
// UnmarshalJSON will unmarshal the Code and Message, then set the error's Kind.
func (e *Error) UnmarshalJSON(data []byte) error {
	rawError := struct {
		Code    ErrorCode `json:"code"`
		Message string    `json:"message"`
	}{}
	if err := json.Unmarshal(data, &rawError); err != nil {
		return err
	}
	e.Message = rawError.Message
	e.Code = rawError.Code
	e.setErrorKind()
	return nil
}

func (e *Error) Unwrap() error {
	return e.wrapped
}
