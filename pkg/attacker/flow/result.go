package flow

import (
	"fmt"
	"net/http"
	"net/url"
)

type RequestSnapshot struct {
	Method  string
	RawURL  string
	Host    string
	Query   url.Values
	Headers http.Header
	Body    []byte
}

type StepResult struct {
	StepID          string
	Actor           string
	RequestName     string
	Request         RequestSnapshot
	SentRequest     *RequestSnapshot
	StatusCode      int
	ResponseHeaders http.Header
	ResponseBody    []byte
	Extracted       Variables
}

type RunResult struct {
	FlowName     string
	Steps        []StepResult
	Variables    Variables
	FailedStepID string
}

type ComparisonResult struct {
	MutationStepID string
	Baseline       RunResult
	Mutated        RunResult
}

type ErrorKind string

const (
	InvalidFlowError ErrorKind = "invalid_flow"
	RequestError     ErrorKind = "request"
	ClientError      ErrorKind = "client"
	BindingError     ErrorKind = "binding"
	MutationError    ErrorKind = "mutation"
	HookError        ErrorKind = "hook"
	TransportError   ErrorKind = "transport"
	StatusError      ErrorKind = "status"
	ExtractionError  ErrorKind = "extraction"
)

type StepError struct {
	Kind   ErrorKind
	StepID string
	Err    error
}

func (e *StepError) Error() string {
	if e.StepID == "" {
		return fmt.Sprintf("flow %s: %v", e.Kind, e.Err)
	}
	return fmt.Sprintf("flow step %q %s: %v", e.StepID, e.Kind, e.Err)
}

func (e *StepError) Unwrap() error { return e.Err }
