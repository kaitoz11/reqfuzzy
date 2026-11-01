package flow

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker/cookiefield"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/jsonutil"
	"github.com/tidwall/gjson"
)

var errExtractionMissing = errors.New("response extraction is missing")

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
		if len(values) == 0 {
			return Value{}, fmt.Errorf("%w: response cookie is absent", errExtractionMissing)
		}
		if len(values) != 1 {
			return Value{}, fmt.Errorf("response cookie selector must match exactly one Set-Cookie")
		}
		raw, _ := json.Marshal(values[0])
		return ParseValue(raw)
	}
	if err := jsonutil.ValidateUnique(step.ResponseBody); err != nil {
		return Value{}, fmt.Errorf("response JSON is invalid or ambiguous")
	}
	found := gjson.GetBytes(step.ResponseBody, extraction.JSONPath)
	if !found.Exists() || found.Type == gjson.Null {
		return Value{}, fmt.Errorf("%w: json path %q did not select a scalar", errExtractionMissing, extraction.JSONPath)
	}
	if found.Type == gjson.JSON {
		return Value{}, fmt.Errorf("json path %q did not select a scalar", extraction.JSONPath)
	}
	value, err := ParseValue([]byte(found.Raw))
	if err != nil {
		return Value{}, fmt.Errorf("json path %q did not select a valid scalar", extraction.JSONPath)
	}
	return value, nil
}

func extractionStatus(extraction Extraction, status int) bool {
	if len(extraction.OnStatus) == 0 {
		return true
	}
	for _, candidate := range extraction.OnStatus {
		if candidate == status {
			return true
		}
	}
	return false
}
