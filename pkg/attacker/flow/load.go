package flow

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

func LoadYAML(data []byte) (Flow, error) {
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
	if err := Validate(result); err != nil {
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
	if strings.TrimSpace(candidate.Name) == "" {
		return errors.New("flow name is required")
	}
	if len(candidate.Steps) == 0 {
		return errors.New("flow needs at least one step")
	}

	stepIDs := make(map[string]struct{}, len(candidate.Steps))
	variables := make(map[string]struct{})
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
			case "header", "query", "json":
			default:
				return fmt.Errorf("flow step %q: unsupported binding location %q", step.ID, binding.Location)
			}
			if binding.Location == "json" && binding.Prefix != "" {
				return fmt.Errorf("flow step %q: JSON binding cannot use prefix", step.ID)
			}
			if _, exists := variables[binding.Variable]; !exists {
				return fmt.Errorf("flow step %q: variable %q must be extracted by an earlier step", step.ID, binding.Variable)
			}
		}
		for _, extraction := range step.Extract {
			if extraction.Name == "" || extraction.JSONPath == "" {
				return fmt.Errorf("flow step %q: extraction name and json path are required", step.ID)
			}
			if _, exists := variables[extraction.Name]; exists {
				return fmt.Errorf("flow step %q: duplicate variable %q", step.ID, extraction.Name)
			}
			variables[extraction.Name] = struct{}{}
		}
	}
	return nil
}
