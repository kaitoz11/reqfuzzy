package campaign

import (
	"encoding/json"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
	"github.com/tidwall/gjson"
)

func observation(check Check, trial Trial) (Scalar, error) {
	result := trial.Flow
	if check.Phase == "verify" {
		result = trial.Verification
	}
	for _, step := range result.Steps {
		if step.StepID != check.Step {
			continue
		}
		switch check.Select {
		case "status":
			if step.StatusCode == 0 {
				return nil, fmt.Errorf("no HTTP response")
			}
			return Scalar(strconv.Itoa(step.StatusCode)), nil
		case "body":
			if !utf8.Valid(step.ResponseBody) {
				return nil, fmt.Errorf("body is not UTF-8")
			}
			raw, _ := json.Marshal(string(step.ResponseBody))
			return Scalar(raw), nil
		case "json":
			if !gjson.ValidBytes(step.ResponseBody) {
				return nil, fmt.Errorf("response is not JSON")
			}
			selected := gjson.GetBytes(step.ResponseBody, check.Path)
			if !selected.Exists() || selected.Type == gjson.JSON {
				return nil, fmt.Errorf("JSON scalar observation is missing")
			}
			return scalar([]byte(selected.Raw))
		}
	}
	return nil, fmt.Errorf("observed step was not executed")
}

func EvaluateCheck(check Check, trial, baseline Trial) CheckResult {
	result := CheckResult{ID: check.ID, Outcome: Inconclusive}
	actual, err := observation(check, trial)
	if err != nil {
		result.Reason = err.Error()
		return result
	}
	result.Actual = actual
	expected := check.Value
	if check.Baseline {
		expected, err = observation(check, baseline)
	} else if check.Variable != "" {
		value, ok := trial.Verification.Variables[check.Variable]
		if !ok {
			value, ok = trial.Flow.Variables[check.Variable]
		}
		if !ok {
			err = fmt.Errorf("check variable is unavailable")
		} else {
			expected, err = scalar(value.RawJSON)
		}
	}
	if err != nil || len(expected) == 0 {
		result.Reason = "expected value is unavailable"
		return result
	}
	result.Expected = expected
	passed, err := compare(actual, expected, check.Op)
	if err != nil {
		result.Reason = err.Error()
		return result
	}
	result.Outcome = Fail
	if passed {
		result.Outcome = Pass
	}
	return result
}

func numeric(raw []byte) (*big.Rat, error) {
	if len(raw) > 4096 {
		return nil, fmt.Errorf("numeric operand exceeds supported precision")
	}
	text := string(raw)
	if index := strings.IndexAny(text, "eE"); index >= 0 {
		exponent, err := strconv.ParseInt(text[index+1:], 10, 32)
		if err != nil || exponent > 10000 || exponent < -10000 {
			return nil, fmt.Errorf("numeric exponent exceeds supported range")
		}
	}
	number, ok := new(big.Rat).SetString(text)
	if !ok {
		return nil, fmt.Errorf("invalid numeric operand")
	}
	return number, nil
}

func compare(actual, expected Scalar, operator string) (bool, error) {
	a, b := gjson.ParseBytes(actual), gjson.ParseBytes(expected)
	if operator == "contains" || operator == "not_contains" || operator == "matches" {
		if a.Type != gjson.String || b.Type != gjson.String {
			return false, fmt.Errorf("text operator requires strings")
		}
		if operator == "matches" {
			pattern, err := regexp.Compile(b.String())
			if err != nil {
				return false, fmt.Errorf("invalid check regex")
			}
			return pattern.MatchString(a.String()), nil
		}
		found := strings.Contains(a.String(), b.String())
		if operator == "not_contains" {
			found = !found
		}
		return found, nil
	}
	if a.Type != b.Type {
		return false, fmt.Errorf("check operands have different JSON types")
	}
	order := 0
	if a.Type == gjson.Number {
		left, err := numeric(actual)
		if err != nil {
			return false, err
		}
		right, err := numeric(expected)
		if err != nil {
			return false, err
		}
		order = left.Cmp(right)
	} else {
		if operator != "eq" && operator != "ne" {
			return false, fmt.Errorf("ordered comparison requires numbers")
		}
		left, right := a.String(), b.String()
		if a.Type == gjson.Null {
			left, right = "null", "null"
		}
		order = strings.Compare(left, right)
	}
	switch operator {
	case "eq":
		return order == 0, nil
	case "ne":
		return order != 0, nil
	case "lt":
		return order < 0, nil
	case "lte":
		return order <= 0, nil
	case "gt":
		return order > 0, nil
	case "gte":
		return order >= 0, nil
	}
	return false, fmt.Errorf("unsupported check operator")
}

// DeclaredVariables provides safe placeholders for static verification-flow validation.
func DeclaredVariables(definition flow.Flow, initial flow.Variables) flow.Variables {
	values := flow.CloneVariables(initial)
	placeholder, _ := flow.ParseValue([]byte(`""`))
	for _, step := range definition.Steps {
		for _, extract := range step.Extract {
			values[extract.Name] = placeholder
		}
		for _, name := range step.Provides {
			values[name] = placeholder
		}
	}
	return values
}
