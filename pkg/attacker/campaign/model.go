// Package campaign evaluates reusable mutation cases against a stateful API journey.
package campaign

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
	"github.com/tidwall/gjson"
	"gopkg.in/yaml.v3"
)

type Scalar []byte

func scalar(raw []byte) (Scalar, error) {
	raw = bytes.TrimSpace(raw)
	if !gjson.ValidBytes(raw) || gjson.ParseBytes(raw).Type == gjson.JSON {
		return nil, fmt.Errorf("expected a JSON scalar")
	}
	return append(Scalar(nil), raw...), nil
}
func (s *Scalar) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode {
		return fmt.Errorf("value must be a JSON scalar")
	}
	var raw []byte
	switch node.Tag {
	case "!!str":
		raw, _ = json.Marshal(node.Value)
	case "!!null":
		raw = []byte("null")
	case "!!bool":
		raw = []byte(strings.ToLower(node.Value))
	case "!!int", "!!float":
		raw = []byte(node.Value)
	default:
		return fmt.Errorf("unsupported scalar type")
	}
	value, err := scalar(raw)
	if err != nil {
		return err
	}
	*s = value
	return nil
}
func (s Scalar) MarshalJSON() ([]byte, error) {
	if len(s) == 0 {
		return []byte("null"), nil
	}
	value, err := scalar(s)
	return value, err
}
func (s *Scalar) UnmarshalJSON(raw []byte) error {
	value, err := scalar(raw)
	if err == nil {
		*s = value
	}
	return err
}

type Target struct {
	Step     string `yaml:"step" json:"step"`
	Location string `yaml:"location" json:"location"`
	Path     string `yaml:"path" json:"path"`
}
type Case struct {
	ID     string `yaml:"id" json:"id"`
	Action string `yaml:"action" json:"action"`
	Value  Scalar `yaml:"value,omitempty" json:"value,omitempty"`
}

func (c *Case) UnmarshalYAML(node *yaml.Node) error {
	type plain Case
	var decoded plain
	if err := recordFields(node, "id", "action", "value"); err != nil {
		return err
	}
	if err := node.Decode(&decoded); err != nil {
		return err
	}
	*c = Case(decoded)
	if hasNullValue(node) {
		c.Value = Scalar("null")
	}
	return nil
}

type Check struct {
	ID       string `yaml:"id" json:"id"`
	Phase    string `yaml:"phase,omitempty" json:"phase,omitempty"`
	Step     string `yaml:"step" json:"step"`
	Select   string `yaml:"select" json:"select"`
	Path     string `yaml:"path,omitempty" json:"path,omitempty"`
	Op       string `yaml:"op" json:"op"`
	Value    Scalar `yaml:"value,omitempty" json:"value,omitempty"`
	Variable string `yaml:"variable,omitempty" json:"variable,omitempty"`
	Baseline bool   `yaml:"baseline,omitempty" json:"baseline,omitempty"`
}

func (c *Check) UnmarshalYAML(node *yaml.Node) error {
	type plain Check
	var decoded plain
	if err := recordFields(node, "id", "phase", "step", "select", "path", "op", "value", "variable", "baseline"); err != nil {
		return err
	}
	if err := node.Decode(&decoded); err != nil {
		return err
	}
	*c = Check(decoded)
	if hasNullValue(node) {
		c.Value = Scalar("null")
	}
	return nil
}

func recordFields(node *yaml.Node, allowed ...string) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("expected a mapping")
	}
	names := map[string]bool{}
	for _, name := range allowed {
		names[name] = true
	}
	for i := 0; i < len(node.Content); i += 2 {
		if !names[node.Content[i].Value] {
			return fmt.Errorf("unknown field %q", node.Content[i].Value)
		}
	}
	return nil
}
func hasNullValue(node *yaml.Node) bool {
	for i := 0; i < len(node.Content); i += 2 {
		if node.Content[i].Value == "value" && node.Content[i+1].Tag == "!!null" {
			return true
		}
	}
	return false
}

type Redaction struct {
	Headers   []string `yaml:"headers,omitempty" json:"headers,omitempty"`
	QueryKeys []string `yaml:"query_keys,omitempty" json:"query_keys,omitempty"`
	JSONPaths []string `yaml:"json_paths,omitempty" json:"json_paths,omitempty"`
}
type Spec struct {
	Version         int       `yaml:"version" json:"version"`
	Name            string    `yaml:"name" json:"name"`
	Target          Target    `yaml:"target" json:"target"`
	ObserveStatuses []int     `yaml:"observe_statuses" json:"observe_statuses"`
	Verify          string    `yaml:"verify,omitempty" json:"verify,omitempty"`
	Cases           []Case    `yaml:"cases" json:"cases"`
	Checks          []Check   `yaml:"checks" json:"checks"`
	Redact          Redaction `yaml:"redact,omitempty" json:"redact,omitempty"`
}

type Outcome string

const (
	Pass         Outcome = "pass"
	Fail         Outcome = "fail"
	Inconclusive Outcome = "inconclusive"
)

type CheckResult struct {
	ID       string  `json:"id"`
	Outcome  Outcome `json:"outcome"`
	Reason   string  `json:"reason,omitempty"`
	Actual   Scalar  `json:"-"`
	Expected Scalar  `json:"-"`
}
type Trial struct {
	ID           string         `json:"id"`
	Outcome      Outcome        `json:"outcome"`
	Reason       string         `json:"reason,omitempty"`
	TargetStatus int            `json:"target_status,omitempty"`
	ErrorKind    flow.ErrorKind `json:"error_kind,omitempty"`
	FailedStep   string         `json:"failed_step,omitempty"`
	Flow         flow.RunResult `json:"-"`
	Verification flow.RunResult `json:"-"`
	Checks       []CheckResult  `json:"checks"`
}
type Result struct {
	Name     string  `json:"name"`
	Outcome  Outcome `json:"outcome"`
	Baseline Trial   `json:"baseline"`
	Cases    []Trial `json:"cases"`
}
