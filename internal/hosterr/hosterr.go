// Package hosterr defines the hostops exit-code contract and a typed error
// that carries one of those codes up to main.
package hosterr

import (
	"errors"
	"fmt"
)

// Exit codes. This table is a public contract (see CLAUDE.md and README).
const (
	OK           = 0 // success
	General      = 1 // unexpected failure
	Permission   = 2 // auth/permission, including --read-only refusals
	Validation   = 3 // bad input; always fails closed before anything runs
	Confirm      = 4 // write command needs a valid --confirm token
	Verification = 5 // the action ran but post-verification failed
	Partial      = 6 // partial or inconclusive result
)

// Kind returns the stable machine name for an exit code.
func Kind(code int) string {
	switch code {
	case OK:
		return "ok"
	case Permission:
		return "permission"
	case Validation:
		return "validation"
	case Confirm:
		return "confirmation_required"
	case Verification:
		return "verification_failed"
	case Partial:
		return "partial"
	default:
		return "general"
	}
}

// Error is an error that maps to an exit code.
type Error struct {
	Code int
	Msg  string
	Err  error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Msg, e.Err)
	}
	return e.Msg
}

func (e *Error) Unwrap() error { return e.Err }

// New builds an Error with a formatted message.
func New(code int, format string, a ...any) *Error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, a...)}
}

// Wrap attaches a code and message to an underlying error.
func Wrap(code int, err error, msg string) *Error {
	return &Error{Code: code, Msg: msg, Err: err}
}

// Code extracts the exit code from err. nil is OK; untyped errors are General.
func Code(err error) int {
	if err == nil {
		return OK
	}
	var he *Error
	if errors.As(err, &he) {
		return he.Code
	}
	return General
}
