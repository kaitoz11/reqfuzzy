package flow

import (
	"bytes"
	"fmt"

	"github.com/tidwall/gjson"
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
	return BuildMutation(MutationSpec{Action: "set", Location: location, Path: path, Value: value.RawJSON})
}

// ParseMutationValue additionally permits JSON null, which is useful for request tests.
func ParseMutationValue(raw []byte) (Value, error) {
	raw = bytes.TrimSpace(raw)
	if bytes.Equal(raw, []byte("null")) {
		return Value{RawJSON: []byte("null"), Text: "null"}, nil
	}
	return ParseValue(raw)
}
