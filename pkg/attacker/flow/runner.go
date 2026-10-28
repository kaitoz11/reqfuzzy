package flow

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/rawreq"
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
	if err := validateMutation(definition, mutation); err != nil {
		return result, &StepError{Kind: InvalidFlowError, Err: err}
	}

	contexts := make(map[string]*attacker.RequestContext, len(definition.Steps))
	clients := make(map[string]*attacker.HClient)
	for _, step := range definition.Steps {
		requestContext, err := r.Store.GetRequestContext(step.Request)
		if err != nil {
			return failRun(result, step.ID, RequestError, err)
		}
		contexts[step.Request] = requestContext
		if step.BeforeSend != "" && r.BeforeSend[step.BeforeSend] == nil {
			return failRun(result, step.ID, HookError, fmt.Errorf("hook %q not registered", step.BeforeSend))
		}
		actor := actorName(step)
		if clients[actor] == nil {
			client, err := r.NewClient(actor)
			if err != nil {
				return failRun(result, step.ID, ClientError, err)
			}
			if client == nil {
				return failRun(result, step.ID, ClientError, fmt.Errorf("client factory returned nil for actor %q", actor))
			}
			clients[actor] = client
		}
	}

	for _, step := range definition.Steps {
		actor := actorName(step)
		if err := ctx.Err(); err != nil {
			return failRun(result, step.ID, TransportError, err)
		}
		client := clients[actor]
		request, err := client.NewRequestFromParsed(contexts[step.Request].ParsedRequest)
		if err != nil {
			return failRun(result, step.ID, RequestError, err)
		}
		for key := range request.Headers {
			if strings.EqualFold(key, "Cookie") {
				delete(request.Headers, key)
			}
		}
		request.SetContext(ctx)
		request.SetContextData(rawreq.RequestBodyType, contexts[step.Request].ParsedRequest.BodyType)
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

func actorName(step Step) string {
	if step.Actor == "" {
		return "default"
	}
	return step.Actor
}

func (r Runner) Compare(ctx context.Context, definition Flow, mutation StepMutation) (ComparisonResult, error) {
	comparison := ComparisonResult{MutationStepID: mutation.StepID}
	if err := Validate(definition); err != nil {
		return comparison, &StepError{Kind: InvalidFlowError, Err: err}
	}
	if err := validateMutation(definition, &mutation); err != nil {
		return comparison, &StepError{Kind: InvalidFlowError, Err: err}
	}
	var err error
	comparison.Baseline, err = r.Run(ctx, definition, nil)
	if err != nil {
		return comparison, err
	}
	comparison.Mutated, err = r.Run(ctx, definition, &mutation)
	return comparison, err
}

func validateMutation(definition Flow, mutation *StepMutation) error {
	if mutation == nil {
		return nil
	}
	if mutation.Apply == nil {
		return fmt.Errorf("mutation callback is required")
	}
	for _, step := range definition.Steps {
		if step.ID == mutation.StepID {
			return nil
		}
	}
	return fmt.Errorf("mutation step %q not found", mutation.StepID)
}

func failRun(result RunResult, stepID string, kind ErrorKind, err error) (RunResult, error) {
	result.FailedStepID = stepID
	return result, &StepError{Kind: kind, StepID: stepID, Err: err}
}

func bindValue(request attacker.Request, binding Binding, value Value) error {
	switch binding.Location {
	case "header":
		for key := range request.Headers {
			if strings.EqualFold(key, binding.Path) {
				delete(request.Headers, key)
			}
		}
		request.SetHeaderNonCanonical(binding.Path, value.Text)
	case "query":
		updated, err := replaceQueryValue(request.RawURL, binding.Path, value.Text)
		if err != nil {
			return err
		}
		request.QueryParams.Del(binding.Path)
		request.SetURL(updated)
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

func replaceQueryValue(rawURL, key, value string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("parse request URL: %w", err)
	}
	parts := strings.Split(parsed.RawQuery, "&")
	replaced := false
	kept := make([]string, 0, len(parts)+1)
	for _, part := range parts {
		if part == "" {
			continue
		}
		rawKey, _, _ := strings.Cut(part, "=")
		decodedKey, err := url.QueryUnescape(rawKey)
		if err != nil {
			return "", fmt.Errorf("decode query key %q: %w", rawKey, err)
		}
		if decodedKey != key {
			kept = append(kept, part)
			continue
		}
		if !replaced {
			kept = append(kept, rawKey+"="+url.QueryEscape(value))
			replaced = true
		}
	}
	if !replaced {
		kept = append(kept, url.QueryEscape(key)+"="+url.QueryEscape(value))
	}
	parsed.RawQuery = strings.Join(kept, "&")
	return parsed.String(), nil
}

func snapshot(request attacker.Request) RequestSnapshot {
	query := make(url.Values)
	if parsed, err := url.Parse(request.RawURL); err == nil {
		query = parsed.Query()
	}
	for key, values := range request.QueryParams {
		query[key] = append(query[key], values...)
	}
	return RequestSnapshot{
		Method:  request.Method,
		RawURL:  request.RawURL,
		Query:   query,
		Headers: request.Headers.Clone(),
		Body:    append([]byte(nil), request.Body...),
	}
}
