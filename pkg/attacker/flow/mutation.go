package flow

import (
	"bytes"
	"fmt"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker"
	"github.com/tidwall/gjson"
	"golang.org/x/net/http/httpguts"
)

// ParseValue accepts a JSON string, number, or boolean without converting numbers to float64.
func ParseValue(raw []byte) (Value, error) {
	raw = bytes.TrimSpace(raw)
	if !gjson.ValidBytes(raw) {
		return Value{}, fmt.Errorf("invalid JSON scalar")
	}
	parsed := gjson.ParseBytes(raw)
	if parsed.Type == gjson.JSON || parsed.Type == gjson.Null {
		return Value{}, fmt.Errorf("value must be a JSON string, number, or boolean")
	}
	text := string(raw)
	if parsed.Type == gjson.String {
		text = parsed.String()
	}
	return Value{RawJSON: bytes.Clone(raw), Text: text}, nil
}

func SetMutation(location, path string, value Value) (Mutation, error) {
	parsed, err := ParseValue(value.RawJSON)
	if err != nil {
		return nil, err
	}
	if path == "" {
		return nil, fmt.Errorf("mutation path is required")
	}
	switch location {
	case "header":
		if !httpguts.ValidHeaderFieldName(path) || !httpguts.ValidHeaderFieldValue(parsed.Text) {
			return nil, fmt.Errorf("invalid mutation header")
		}
	case "query", "json":
	default:
		return nil, fmt.Errorf("unsupported mutation location %q", location)
	}
	return func(request attacker.Request, _ Variables) error {
		return bindValue(request, Binding{Location: location, Path: path}, parsed)
	}, nil
}
