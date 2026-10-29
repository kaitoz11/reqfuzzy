package flow

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/cookiefield"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

func LoadYAML(data []byte) (Flow, error) {
	return LoadYAMLWithVariables(data, nil)
}

func LoadYAMLWithVariables(data []byte, initial Variables) (Flow, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)

	var result Flow
	if err := decoder.Decode(&result); err != nil {
		return Flow{}, fmt.Errorf("decode flow: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err != nil {
			return Flow{}, fmt.Errorf("decode trailing flow data: %w", err)
		}
		return Flow{}, errors.New("flow must contain exactly one YAML document")
	}
	if err := ValidateWithVariables(result, initial); err != nil {
		return Flow{}, err
	}
	for i := range result.Steps {
		if result.Steps[i].Actor == "" {
			result.Steps[i].Actor = "default"
		}
	}
	return result, nil
}

func Validate(candidate Flow) error {
	return ValidateWithVariables(candidate, nil)
}

func ValidateWithVariables(candidate Flow, initial Variables) error {
	if strings.TrimSpace(candidate.Name) == "" {
		return errors.New("flow name is required")
	}
	if len(candidate.Steps) == 0 {
		return errors.New("flow needs at least one step")
	}

	stepIDs := make(map[string]struct{}, len(candidate.Steps))
	variables := make(map[string]struct{})
	for name, value := range initial {
		if strings.TrimSpace(name) == "" {
			return errors.New("initial variable name is required")
		}
		if _, err := ParseValue(value.RawJSON); err != nil {
			return fmt.Errorf("initial variable %q is not a scalar", name)
		}
		variables[name] = struct{}{}
	}
	for _, step := range candidate.Steps {
		if strings.TrimSpace(step.ID) == "" {
			return errors.New("flow step id is required")
		}
		if _, exists := stepIDs[step.ID]; exists {
			return fmt.Errorf("flow step %q: duplicate id", step.ID)
		}
		stepIDs[step.ID] = struct{}{}
		if strings.TrimSpace(step.Request) == "" {
			return fmt.Errorf("flow step %q: request is required", step.ID)
		}
		if step.ExpectStatus != nil && (*step.ExpectStatus < 100 || *step.ExpectStatus > 599) {
			return fmt.Errorf("flow step %q: expect_status must be 100 through 599", step.ID)
		}
		for _, binding := range step.Bind {
			if binding.Path == "" || binding.Variable == "" {
				return fmt.Errorf("flow step %q: binding path and variable are required", step.ID)
			}
			switch binding.Location {
			case "header", "query", "json", "path", "form", "cookie":
			default:
				return fmt.Errorf("flow step %q: unsupported binding location %q", step.ID, binding.Location)
			}
			if binding.Location == "cookie" {
				if err := cookiefield.Valid(binding.Path, ""); err != nil {
					return fmt.Errorf("flow step %q: %w", step.ID, err)
				}
			}
			if binding.Location == "path" {
				if _, err := pathIndex(binding.Path); err != nil {
					return fmt.Errorf("flow step %q: %w", step.ID, err)
				}
			}
			if binding.Location == "json" && binding.Prefix != "" {
				return fmt.Errorf("flow step %q: JSON binding cannot use prefix", step.ID)
			}
			if _, exists := variables[binding.Variable]; !exists {
				return fmt.Errorf("flow step %q: variable %q must be extracted by an earlier step", step.ID, binding.Variable)
			}
		}
		for _, extraction := range step.Extract {
			if extraction.Name == "" || (extraction.JSONPath == "") == (extraction.Cookie == "") {
				return fmt.Errorf("flow step %q: extraction requires a name and exactly one json or cookie selector", step.ID)
			}
			if extraction.Cookie != "" {
				if err := cookiefield.Valid(extraction.Cookie, ""); err != nil {
					return fmt.Errorf("flow step %q: %w", step.ID, err)
				}
			}
			if _, exists := variables[extraction.Name]; exists {
				return fmt.Errorf("flow step %q: duplicate variable %q", step.ID, extraction.Name)
			}
			variables[extraction.Name] = struct{}{}
		}
		if len(step.Provides) > 0 && step.AfterResponse == "" {
			return fmt.Errorf("flow step %q: provides requires after_response", step.ID)
		}
		for _, name := range step.Provides {
			if strings.TrimSpace(name) == "" {
				return fmt.Errorf("flow step %q: provided variable name is required", step.ID)
			}
			if _, exists := variables[name]; exists {
				return fmt.Errorf("flow step %q: duplicate variable %q", step.ID, name)
			}
			variables[name] = struct{}{}
		}
	}
	return nil
}
