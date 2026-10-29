package flow

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/cookiefield"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/jsonutil"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/urlform"
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
	lookup := spec.Path
	if spec.Location == "json" {
		var err error
		lookup, err = jsonutil.MutationLookupPath(spec.Path)
		if err != nil {
			return nil, err
		}
	}
	switch spec.Location {
	case "cookie":
		if err := cookiefield.Valid(spec.Path, ""); err != nil {
			return nil, err
		}
	case "header":
		if !httpguts.ValidHeaderFieldName(spec.Path) {
			return nil, fmt.Errorf("invalid mutation header")
		}
		if strings.EqualFold(spec.Path, "Content-Length") || strings.EqualFold(spec.Path, "Transfer-Encoding") || (strings.EqualFold(spec.Path, "Host") && spec.Action == "remove") {
			return nil, fmt.Errorf("mutation is unsupported for a transport-managed header")
		}
	case "path":
		if _, err := pathIndex(spec.Path); err != nil {
			return nil, err
		}
	case "query", "json", "form":
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
		if spec.Location == "cookie" {
			if err := cookiefield.Valid(spec.Path, payload.Text); err != nil {
				return nil, err
			}
		}
	}
	return func(request attacker.Request, _ Variables) error {
		if spec.Location == "json" {
			if err := jsonutil.ValidateUnique(request.Body); err != nil {
				return err
			}
		}
		if spec.Action == "set" {
			if err := bindValue(request, Binding{Location: spec.Location, Path: spec.Path}, payload); err != nil {
				return err
			}
			if spec.Location == "json" {
				return jsonMutationApplied(request, lookup, payload.RawJSON, false)
			}
			return nil
		}
		current, err := existingValue(request, spec.Location, lookup, spec.Action != "remove")
		if err != nil {
			return err
		}
		if spec.Action == "remove" {
			before := append([]byte(nil), request.Body...)
			if err := removeValue(request, spec.Location, spec.Path); err != nil {
				return err
			}
			if spec.Location == "json" {
				return jsonRemovalApplied(before, request.Body, spec.Path)
			}
			return nil
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
		if err := bindValue(request, Binding{Location: spec.Location, Path: spec.Path}, value); err != nil {
			return err
		}
		if spec.Location == "json" {
			return jsonMutationApplied(request, lookup, value.RawJSON, false)
		}
		return nil
	}, nil
}

func jsonRemovalApplied(before, after []byte, path string) error {
	parent, key, err := jsonutil.MutationParent(path)
	if err != nil {
		return err
	}
	container := gjson.ParseBytes(before)
	remaining := gjson.ParseBytes(after)
	if parent != "" {
		container = gjson.GetBytes(before, parent)
		remaining = gjson.GetBytes(after, parent)
	}
	if container.IsArray() {
		index, err := strconv.Atoi(key)
		items := container.Array()
		if err != nil || index < 0 || index >= len(items) || !remaining.IsArray() {
			return fmt.Errorf("JSON array removal did not apply")
		}
		var expected bytes.Buffer
		expected.WriteByte('[')
		first := true
		for position, item := range items {
			if position == index {
				continue
			}
			if !first {
				expected.WriteByte(',')
			}
			first = false
			expected.WriteString(item.Raw)
		}
		expected.WriteByte(']')
		same, err := jsonutil.EqualJSON(expected.Bytes(), []byte(remaining.Raw))
		if err != nil || !same {
			return fmt.Errorf("JSON array removal did not apply structurally")
		}
		return nil
	}
	lookup, _ := jsonutil.MutationLookupPath(path)
	if gjson.GetBytes(after, lookup).Exists() {
		return fmt.Errorf("JSON removal did not apply at the requested field")
	}
	return nil
}

func jsonMutationApplied(request attacker.Request, lookup string, expected []byte, remove bool) error {
	found := gjson.GetBytes(request.Body, lookup)
	if remove {
		if found.Exists() {
			return fmt.Errorf("JSON removal did not apply at the requested field")
		}
		return nil
	}
	if !found.Exists() || !bytes.Equal([]byte(found.Raw), expected) {
		return fmt.Errorf("JSON mutation did not apply at the requested field")
	}
	return nil
}

func existingValue(request attacker.Request, location, path string, uniqueString bool) (Value, error) {
	switch location {
	case "cookie":
		values, err := request.CookieValues(path)
		if err != nil {
			return Value{}, err
		}
		if len(values) == 0 {
			return Value{}, fmt.Errorf("mutation cookie does not exist")
		}
		if uniqueString && len(values) != 1 {
			return Value{}, fmt.Errorf("append/prepend cannot target repeated cookie names")
		}
		return Value{Text: values[0]}, nil
	case "path":
		_, parts, index, err := pathAddress(request.RawURL, path)
		if err != nil {
			return Value{}, err
		}
		text, err := url.PathUnescape(parts[index])
		if err != nil {
			return Value{}, fmt.Errorf("invalid path segment")
		}
		return Value{Text: text}, nil
	case "form":
		fields, err := urlform.Parse(request.Headers, request.Body)
		if err != nil {
			return Value{}, err
		}
		values := fields[path]
		if len(values) == 0 {
			return Value{}, fmt.Errorf("mutation form key does not exist")
		}
		if uniqueString && len(values) != 1 {
			return Value{}, fmt.Errorf("append/prepend cannot target repeated form keys")
		}
		return Value{Text: values[0]}, nil
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
	case "cookie":
		return request.RemoveCookieValue(path)
	case "path":
		updated, err := removePathSegment(request.RawURL, path)
		if err != nil {
			return err
		}
		request.SetURL(updated)
	case "form":
		body, err := urlform.Remove(request.Headers, request.Body, path)
		if err != nil {
			return err
		}
		request.SetBodyBytes(body)
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
