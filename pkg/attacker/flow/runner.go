package flow

import (
	"context"
	"fmt"
	"net/url"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

type ClientFactory func(actor string) (*attacker.HClient, error)
type BeforeSend func(request attacker.Request, variables Variables) error
type Mutation func(request attacker.Request, variables Variables) error

type StepMutation struct {
	StepID string
	Apply  Mutation
}

type Runner struct {
	Store      *attacker.RequestStore
	NewClient  ClientFactory
	BeforeSend map[string]BeforeSend
}

func (r Runner) Run(ctx context.Context, definition Flow, mutation *StepMutation) (RunResult, error) {
	result := RunResult{FlowName: definition.Name, Variables: make(Variables)}
	if err := Validate(definition); err != nil {
		return result, &StepError{Kind: InvalidFlowError, Err: err}
	}
	if r.Store == nil || r.NewClient == nil {
		return result, &StepError{Kind: InvalidFlowError, Err: fmt.Errorf("request store and client factory are required")}
	}
	if mutation != nil {
		if mutation.Apply == nil {
			return result, &StepError{Kind: InvalidFlowError, Err: fmt.Errorf("mutation callback is required")}
		}
		found := false
		for _, step := range definition.Steps {
			found = found || step.ID == mutation.StepID
		}
		if !found {
			return result, &StepError{Kind: InvalidFlowError, Err: fmt.Errorf("mutation step %q not found", mutation.StepID)}
		}
	}

	contexts := make(map[string]*attacker.RequestContext, len(definition.Steps))
	for _, step := range definition.Steps {
		requestContext, err := r.Store.GetRequestContext(step.Request)
		if err != nil {
			return result, &StepError{Kind: RequestError, StepID: step.ID, Err: err}
		}
		contexts[step.Request] = requestContext
		if step.BeforeSend != "" && r.BeforeSend[step.BeforeSend] == nil {
			return result, &StepError{Kind: HookError, StepID: step.ID, Err: fmt.Errorf("hook %q not registered", step.BeforeSend)}
		}
	}

	clients := make(map[string]*attacker.HClient)
	for _, step := range definition.Steps {
		actor := step.Actor
		if actor == "" {
			actor = "default"
		}
		if err := ctx.Err(); err != nil {
			return failRun(result, step.ID, TransportError, err)
		}
		client := clients[actor]
		if client == nil {
			var err error
			client, err = r.NewClient(actor)
			if err != nil {
				return failRun(result, step.ID, ClientError, err)
			}
			if client == nil {
				return failRun(result, step.ID, ClientError, fmt.Errorf("client factory returned nil for actor %q", actor))
			}
			clients[actor] = client
		}
		request, err := client.NewRequestFromParsed(contexts[step.Request].ParsedRequest)
		if err != nil {
			return failRun(result, step.ID, RequestError, err)
		}
		request.SetContext(ctx)
		for _, binding := range step.Bind {
			value := result.Variables[binding.Variable]
			if err := bindValue(request, binding, value); err != nil {
				return failRun(result, step.ID, BindingError, err)
			}
		}
		if mutation != nil && mutation.StepID == step.ID {
			if err := mutation.Apply(request, result.Variables); err != nil {
				return failRun(result, step.ID, MutationError, err)
			}
		}
		if step.BeforeSend != "" {
			if err := r.BeforeSend[step.BeforeSend](request, result.Variables); err != nil {
				return failRun(result, step.ID, HookError, err)
			}
		}
		trace := StepResult{
			StepID:      step.ID,
			Actor:       actor,
			RequestName: step.Request,
			Request:     snapshot(request),
			Extracted:   make(Variables),
		}
		response, err := client.SendRequest(request)
		if err != nil {
			result.Steps = append(result.Steps, trace)
			return failRun(result, step.ID, TransportError, err)
		}
		trace.StatusCode = response.StatusCode
		trace.ResponseBody = append([]byte(nil), response.Bytes()...)
		result.Steps = append(result.Steps, trace)
		if step.ExpectStatus != nil && trace.StatusCode != *step.ExpectStatus {
			return failRun(result, step.ID, StatusError, fmt.Errorf("got HTTP %d, want %d", trace.StatusCode, *step.ExpectStatus))
		}
		for _, extraction := range step.Extract {
			found := gjson.GetBytes(trace.ResponseBody, extraction.JSONPath)
			if !found.Exists() || found.Type == gjson.JSON || found.Type == gjson.Null {
				return failRun(result, step.ID, ExtractionError, fmt.Errorf("json path %q did not select a scalar", extraction.JSONPath))
			}
			value := Value{RawJSON: []byte(found.Raw), Text: found.String()}
			result.Variables[extraction.Name] = value
			trace.Extracted[extraction.Name] = value
		}
		result.Steps[len(result.Steps)-1] = trace
	}
	return result, nil
}

func failRun(result RunResult, stepID string, kind ErrorKind, err error) (RunResult, error) {
	result.FailedStepID = stepID
	return result, &StepError{Kind: kind, StepID: stepID, Err: err}
}

func bindValue(request attacker.Request, binding Binding, value Value) error {
	switch binding.Location {
	case "header":
		request.SetHeaderNonCanonical(binding.Path, value.Text)
	case "query":
		request.SetQueryParam(binding.Path, value.Text)
	case "json":
		if !gjson.ValidBytes(request.Body) {
			return fmt.Errorf("request body is not JSON")
		}
		updated, err := sjson.SetRawBytes(request.Body, binding.Path, value.RawJSON)
		if err != nil {
			return fmt.Errorf("set JSON path %q: %w", binding.Path, err)
		}
		request.SetBodyBytes(updated)
	default:
		return fmt.Errorf("unsupported binding location %q", binding.Location)
	}
	return nil
}

func snapshot(request attacker.Request) RequestSnapshot {
	query := make(url.Values, len(request.QueryParams))
	for key, values := range request.QueryParams {
		query[key] = append([]string(nil), values...)
	}
	return RequestSnapshot{
		Method:  request.Method,
		RawURL:  request.RawURL,
		Query:   query,
		Headers: request.Headers.Clone(),
		Body:    append([]byte(nil), request.Body...),
	}
}
