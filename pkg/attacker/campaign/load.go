package campaign

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
	"github.com/tidwall/gjson"
	"gopkg.in/yaml.v3"
)

func LoadYAML(data []byte) (Spec, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var spec Spec
	if err := decoder.Decode(&spec); err != nil {
		return Spec{}, fmt.Errorf("decode journey test: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Spec{}, fmt.Errorf("journey test needs one YAML document")
	}
	if err := Validate(spec); err != nil {
		return Spec{}, err
	}
	return spec, nil
}

func SafeID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' {
			continue
		}
		return false
	}
	return true
}

func Validate(spec Spec) error {
	if spec.Version != 1 || strings.TrimSpace(spec.Name) == "" {
		return fmt.Errorf("journey test requires version 1 and name")
	}
	if spec.Target.Step == "" || spec.Target.Location == "" || spec.Target.Path == "" {
		return fmt.Errorf("test target needs step, location and path")
	}
	if len(spec.ObserveStatuses) == 0 {
		return fmt.Errorf("observe_statuses must explicitly list assessable target responses")
	}
	statuses := map[int]bool{}
	for _, status := range spec.ObserveStatuses {
		if status < 100 || status > 599 || statuses[status] {
			return fmt.Errorf("invalid or repeated observed status")
		}
		statuses[status] = true
	}
	if len(spec.Cases) == 0 || len(spec.Checks) == 0 {
		return fmt.Errorf("journey test needs cases and checks")
	}
	ids := map[string]bool{}
	for _, candidate := range spec.Cases {
		if !SafeID(candidate.ID) || candidate.ID == "baseline" || ids[candidate.ID] {
			return fmt.Errorf("case IDs must be unique safe names and cannot be baseline")
		}
		ids[candidate.ID] = true
		if _, err := flow.BuildMutation(flow.MutationSpec{Action: candidate.Action, Location: spec.Target.Location, Path: spec.Target.Path, Value: candidate.Value}); err != nil {
			return fmt.Errorf("case %q: %w", candidate.ID, err)
		}
	}
	ids = map[string]bool{}
	for _, check := range spec.Checks {
		if check.ID == "" || ids[check.ID] || check.Step == "" {
			return fmt.Errorf("checks need unique IDs and step names")
		}
		ids[check.ID] = true
		if check.Phase != "" && check.Phase != "flow" && check.Phase != "verify" {
			return fmt.Errorf("check %q has invalid phase", check.ID)
		}
		if check.Phase == "verify" && spec.Verify == "" {
			return fmt.Errorf("verification checks require a verify flow")
		}
		switch check.Select {
		case "json":
			if check.Path == "" {
				return fmt.Errorf("JSON check needs path")
			}
		case "status", "body":
			if check.Path != "" {
				return fmt.Errorf("status/body check cannot specify path")
			}
		default:
			return fmt.Errorf("check %q has invalid selector", check.ID)
		}
		switch check.Op {
		case "eq", "ne", "lt", "lte", "gt", "gte", "contains", "not_contains", "matches":
		default:
			return fmt.Errorf("check %q has invalid operator", check.ID)
		}
		sources := 0
		if len(check.Value) > 0 {
			sources++
			if _, err := scalar(check.Value); err != nil {
				return fmt.Errorf("check %q needs a scalar value", check.ID)
			}
		}
		if check.Variable != "" {
			sources++
		}
		if check.Baseline {
			sources++
		}
		if sources != 1 {
			return fmt.Errorf("check %q requires exactly one value, variable or baseline source", check.ID)
		}
		if check.Op == "matches" {
			if len(check.Value) == 0 || gjson.ParseBytes(check.Value).Type != gjson.String {
				return fmt.Errorf("regex checks require a literal string value")
			}
			if _, err := regexp.Compile(gjson.ParseBytes(check.Value).String()); err != nil {
				return fmt.Errorf("check %q has invalid regex", check.ID)
			}
		}
	}
	return nil
}
