package flow

import (
	"encoding/json"
	"fmt"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker/cookiefield"
	"github.com/tidwall/gjson"
)

func extractValue(step StepResult, extraction Extraction) (Value, error) {
	if extraction.Cookie != "" {
		cookies, err := cookiefield.ResponseCookies(step.ResponseHeaders)
		if err != nil {
			return Value{}, err
		}
		var values []string
		for _, cookie := range cookies {
			if cookie.Name == extraction.Cookie {
				values = append(values, cookie.Value)
			}
		}
		if len(values) != 1 {
			return Value{}, fmt.Errorf("response cookie selector must match exactly one Set-Cookie")
		}
		raw, _ := json.Marshal(values[0])
		return ParseValue(raw)
	}
	found := gjson.GetBytes(step.ResponseBody, extraction.JSONPath)
	if !found.Exists() || found.Type == gjson.JSON || found.Type == gjson.Null {
		return Value{}, fmt.Errorf("json path %q did not select a scalar", extraction.JSONPath)
	}
	value, err := ParseValue([]byte(found.Raw))
	if err != nil {
		return Value{}, fmt.Errorf("json path %q did not select a valid scalar", extraction.JSONPath)
	}
	return value, nil
}
