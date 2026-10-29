package flow

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/jsonutil"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"golang.org/x/net/http/httpguts"
)

type MutationSpec struct {
	Action, Location, Path string
	Value                  []byte
}

func BuildMutation(spec MutationSpec) (Mutation, error) {
	if spec.Path == "" {
		return nil, fmt.Errorf("mutation path is required")
	}
	switch spec.Location {
	case "header":
		if !httpguts.ValidHeaderFieldName(spec.Path) {
			return nil, fmt.Errorf("invalid mutation header")
		}
		if strings.EqualFold(spec.Path, "Content-Length") || strings.EqualFold(spec.Path, "Transfer-Encoding") || (strings.EqualFold(spec.Path, "Host") && spec.Action == "remove") {
			return nil, fmt.Errorf("mutation is unsupported for a transport-managed header")
		}
	case "query", "json":
	default:
		return nil, fmt.Errorf("unsupported mutation location %q", spec.Location)
	}
	if spec.Action != "set" && spec.Action != "remove" && spec.Action != "append" && spec.Action != "prepend" {
		return nil, fmt.Errorf("unsupported mutation action %q", spec.Action)
	}
	var payload Value
	var err error
	if spec.Action == "remove" {
		if len(spec.Value) != 0 {
			return nil, fmt.Errorf("remove does not take a value")
		}
	} else {
		payload, err = ParseMutationValue(spec.Value)
		if err != nil {
			return nil, err
		}
		if spec.Location != "json" && string(payload.RawJSON) == "null" {
			return nil, fmt.Errorf("null is only valid for a JSON mutation")
		}
		if (spec.Action == "append" || spec.Action == "prepend") && gjson.ParseBytes(payload.RawJSON).Type != gjson.String {
			return nil, fmt.Errorf("append/prepend payload must be a string")
		}
		if spec.Location == "header" && !httpguts.ValidHeaderFieldValue(payload.Text) {
			return nil, fmt.Errorf("invalid mutation header value")
		}
	}
	return func(request attacker.Request, _ Variables) error {
		if spec.Location == "json" {
			if err := jsonutil.ValidateUnique(request.Body); err != nil {
				return err
			}
		}
		if spec.Action == "set" {
			return bindValue(request, Binding{Location: spec.Location, Path: spec.Path}, payload)
		}
		current, err := existingValue(request, spec.Location, spec.Path, spec.Action != "remove")
		if err != nil {
			return err
		}
		if spec.Action == "remove" {
			return removeValue(request, spec.Location, spec.Path)
		}
		text := current.Text + payload.Text
		if spec.Action == "prepend" {
			text = payload.Text + current.Text
		}
		raw, _ := json.Marshal(text)
		value := Value{Text: text, RawJSON: raw}
		if spec.Location == "header" && !httpguts.ValidHeaderFieldValue(text) {
			return fmt.Errorf("invalid combined header value")
		}
		return bindValue(request, Binding{Location: spec.Location, Path: spec.Path}, value)
	}, nil
}

func existingValue(request attacker.Request, location, path string, uniqueString bool) (Value, error) {
	switch location {
	case "json":
		if !gjson.ValidBytes(request.Body) {
			return Value{}, fmt.Errorf("request body is not JSON")
		}
		found := gjson.GetBytes(request.Body, path)
		if !found.Exists() {
			return Value{}, fmt.Errorf("mutation field does not exist")
		}
		if uniqueString && found.Type != gjson.String {
			return Value{}, fmt.Errorf("append/prepend requires an existing JSON string")
		}
		return Value{RawJSON: []byte(found.Raw), Text: found.String()}, nil
	case "header":
		var values []string
		for name, parts := range request.Headers {
			if strings.EqualFold(name, path) {
				values = append(values, parts...)
			}
		}
		if len(values) == 0 {
			return Value{}, fmt.Errorf("mutation header does not exist")
		}
		if uniqueString && len(values) != 1 {
			return Value{}, fmt.Errorf("append/prepend cannot target repeated headers")
		}
		return Value{Text: values[0]}, nil
	case "query":
		parsed, err := url.Parse(request.RawURL)
		if err != nil {
			return Value{}, fmt.Errorf("invalid request URL")
		}
		query, err := url.ParseQuery(parsed.RawQuery)
		if err != nil {
			return Value{}, fmt.Errorf("invalid request query")
		}
		values := append(query[path], request.QueryParams[path]...)
		if len(values) == 0 {
			return Value{}, fmt.Errorf("mutation query key does not exist")
		}
		if uniqueString && len(values) != 1 {
			return Value{}, fmt.Errorf("append/prepend cannot target repeated query keys")
		}
		return Value{Text: values[0]}, nil
	}
	return Value{}, fmt.Errorf("unsupported mutation location")
}

func removeValue(request attacker.Request, location, path string) error {
	switch location {
	case "json":
		body, err := sjson.DeleteBytes(request.Body, path)
		if err != nil {
			return fmt.Errorf("remove JSON field: %w", err)
		}
		request.SetBodyBytes(body)
	case "header":
		for key := range request.Headers {
			if strings.EqualFold(key, path) {
				delete(request.Headers, key)
			}
		}
	case "query":
		parsed, err := url.Parse(request.RawURL)
		if err != nil {
			return fmt.Errorf("invalid request URL")
		}
		var kept []string
		for _, part := range strings.Split(parsed.RawQuery, "&") {
			key, _, _ := strings.Cut(part, "=")
			decoded, err := url.QueryUnescape(key)
			if err != nil {
				return fmt.Errorf("invalid query key")
			}
			if decoded != path {
				kept = append(kept, part)
			}
		}
		parsed.RawQuery = strings.Join(kept, "&")
		request.QueryParams.Del(path)
		request.SetURL(parsed.String())
	}
	return nil
}
