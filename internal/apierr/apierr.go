// Package apierr is the closed registry of API error codes.
//
// An open-ended error vocabulary drifts into dozens of codes with obvious
// synonyms (persist_failed / store_error / store_failed; bad_json /
// bad_request / bad_id / missing_field), and clients cannot switch on them
// reliably. Here the
// set is closed, every code is a constant, and `ci/guards.sh` rejects string
// literals in the error-code position (ARCHITECTURE.md — Error codes).
package apierr

// Code is an API error code. One code per condition — synonyms are a defect.
type Code string

const (
	// Client faults.
	BadRequest   Code = "bad_request"  // malformed input of any kind, incl. bad JSON
	NotFound     Code = "not_found"    // the addressed thing does not exist
	Conflict     Code = "conflict"     // state precondition failed
	Unauthorized Code = "unauthorized" // no valid identity
	Forbidden    Code = "forbidden"    // valid identity, insufficient capability
	RateLimited  Code = "rate_limited" // too many requests

	// Server / dependency faults.
	Internal      Code = "internal"       // unexpected; a bug
	StoreFailed   Code = "store_failed"   // persistence rejected the write
	Unavailable   Code = "unavailable"    // dependency down, retry may help
	NotConfigured Code = "not_configured" // feature needs config that is absent
	ScanFailed    Code = "scan_failed"    // a scan ran and errored
	EngineMissing Code = "engine_missing" // an external tool is not installed
)

// All is the complete set, used by the guard test to prove no code is defined
// outside this file.
var All = []Code{
	BadRequest, NotFound, Conflict, Unauthorized, Forbidden, RateLimited,
	Internal, StoreFailed, Unavailable, NotConfigured, ScanFailed, EngineMissing,
}

// HTTPStatus maps a code to its wire status. Keeping the mapping here means a
// handler never picks a status by hand and never drifts from the code.
func (c Code) HTTPStatus() int {
	switch c {
	case BadRequest:
		return 400
	case Unauthorized:
		return 401
	case Forbidden:
		return 403
	case NotFound:
		return 404
	case Conflict:
		return 409
	case RateLimited:
		return 429
	case NotConfigured, EngineMissing:
		return 501
	case Unavailable:
		return 503
	default:
		return 500
	}
}

// Error is the wire shape: {"error":{"code":…,"message":…}}.
type Error struct {
	Code    Code   `json:"code"`
	Message string `json:"message"`
}

func (e Error) Error() string { return string(e.Code) + ": " + e.Message }

// New builds an Error.
func New(c Code, msg string) Error { return Error{Code: c, Message: msg} }
