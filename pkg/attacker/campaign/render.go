package campaign

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
)

type renderPart struct{ kind, text string }

func stringScalar(text string) (Scalar, error) {
	raw, err := json.Marshal(text)
	return Scalar(raw), err
}

func parseRender(source string) ([]renderPart, error) {
	var parts []renderPart
	for source != "" {
		start := strings.Index(source, "{{")
		if start < 0 {
			parts = append(parts, renderPart{"text", source})
			break
		}
		if start > 0 {
			parts = append(parts, renderPart{"text", source[:start]})
		}
		source = source[start+2:]
		end := strings.Index(source, "}}")
		if end < 0 {
			return nil, fmt.Errorf("unclosed payload render token")
		}
		token := strings.TrimSpace(source[:end])
		source = source[end+2:]
		switch {
		case token == "base" || token == "value":
			parts = append(parts, renderPart{token, ""})
		case strings.HasPrefix(token, "var:"):
			name := strings.TrimSpace(strings.TrimPrefix(token, "var:"))
			if name == "" || strings.ContainsAny(name, "{}") {
				return nil, fmt.Errorf("invalid payload variable token")
			}
			parts = append(parts, renderPart{"var", name})
		default:
			return nil, fmt.Errorf("unsupported payload render token")
		}
	}
	return parts, nil
}

func PayloadVariables(spec Spec) []string {
	var names []string
	seen := map[string]bool{}
	for _, candidate := range spec.Cases {
		parts, _ := parseRender(candidate.Render)
		for _, part := range parts {
			if part.kind == "var" && !seen[part.text] {
				seen[part.text] = true
				names = append(names, part.text)
			}
		}
	}
	return names
}

func encodePayload(text string, encoders []string) (string, error) {
	for _, encoder := range encoders {
		switch encoder {
		case "base64":
			if base64.StdEncoding.EncodedLen(len(text)) > MaxPayloadBytes {
				return "", fmt.Errorf("encoded payload exceeds size limit")
			}
			text = base64.StdEncoding.EncodeToString([]byte(text))
		case "hex":
			if len(text) > MaxPayloadBytes/2 {
				return "", fmt.Errorf("encoded payload exceeds size limit")
			}
			text = hex.EncodeToString([]byte(text))
		case "url":
			text = url.QueryEscape(text)
		case "json":
			raw, _ := json.Marshal(text)
			text = string(raw)
		default:
			return "", fmt.Errorf("unsupported payload encoder")
		}
		if len(text) > MaxPayloadBytes {
			return "", fmt.Errorf("encoded payload exceeds size limit")
		}
	}
	return text, nil
}

func BuildCaseMutation(target Target, candidate Case) (flow.Mutation, error) {
	if len(candidate.Encode) > 16 {
		return nil, fmt.Errorf("payload encoding pipeline exceeds 16 stages")
	}
	if len(candidate.Value) > MaxPayloadBytes || len(candidate.Render) > MaxPayloadBytes {
		return nil, fmt.Errorf("payload exceeds size limit")
	}
	if candidate.Render == "" && len(candidate.Encode) == 0 {
		return flow.BuildMutation(flow.MutationSpec{Action: candidate.Action, Location: target.Location, Path: target.Path, Value: candidate.Value})
	}
	if candidate.Action == "remove" || candidate.Action == "add" || candidate.Action == "multiply" {
		return nil, fmt.Errorf("this mutation action does not accept string rendering/encoding")
	}
	parts, err := parseRender(candidate.Render)
	if err != nil {
		return nil, err
	}
	if _, err := encodePayload("", candidate.Encode); err != nil {
		return nil, err
	}
	valueText := ""
	needsValue := candidate.Render == ""
	for _, part := range parts {
		needsValue = needsValue || part.kind == "value"
	}
	if len(candidate.Value) > 0 || needsValue {
		value, err := flow.ParseMutationValue(candidate.Value)
		if err != nil {
			return nil, err
		}
		valueText = value.Text
	}
	placeholder, _ := stringScalar("")
	if _, err := flow.BuildMutation(flow.MutationSpec{Action: candidate.Action, Location: target.Location, Path: target.Path, Value: placeholder}); err != nil {
		return nil, err
	}
	build := func(request attacker.Request, variables flow.Variables) (flow.Mutation, error) {
		text := valueText
		if candidate.Render != "" {
			var output strings.Builder
			var base *flow.Value
			for _, part := range parts {
				var fragment string
				switch part.kind {
				case "text":
					fragment = part.text
				case "value":
					fragment = valueText
				case "base":
					if base == nil {
						value, err := flow.CurrentMutationValue(request, target.Location, target.Path)
						if err != nil {
							return nil, err
						}
						base = &value
					}
					fragment = base.Text
				case "var":
					value, ok := variables[part.text]
					if !ok {
						return nil, fmt.Errorf("payload variable is unavailable")
					}
					parsed, err := flow.ParseValue(value.RawJSON)
					if err != nil {
						return nil, err
					}
					fragment = parsed.Text
				}
				if output.Len()+len(fragment) > MaxPayloadBytes {
					return nil, fmt.Errorf("rendered payload exceeds size limit")
				}
				output.WriteString(fragment)
			}
			text = output.String()
		}
		text, err := encodePayload(text, candidate.Encode)
		if err != nil {
			return nil, err
		}
		raw, err := stringScalar(text)
		if err != nil {
			return nil, err
		}
		return flow.BuildMutation(flow.MutationSpec{Action: candidate.Action, Location: target.Location, Path: target.Path, Value: raw})
	}
	dynamic := false
	for _, part := range parts {
		dynamic = dynamic || part.kind == "base" || part.kind == "var"
	}
	if !dynamic {
		if _, err := build(attacker.Request{}, nil); err != nil {
			return nil, err
		}
	}
	return func(request attacker.Request, variables flow.Variables) error {
		mutation, err := build(request, variables)
		if err != nil {
			return err
		}
		return mutation(request, variables)
	}, nil
}
