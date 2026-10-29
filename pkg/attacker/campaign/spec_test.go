package campaign_test

import (
	"strings"
	"testing"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker/campaign"
)

const validTest = `version: 1
name: transfer-amount
target: {step: transfer, location: json, path: amount}
observe_statuses: [201, 400, 422, 500]
verify: verify.yaml
cases:
  - {id: negative, action: set, value: -10}
  - {id: missing, action: remove}
checks:
  - {id: balance, phase: verify, step: balance, select: json, path: balance, op: lte, variable: initial_balance}
`

func TestLoadTypedJourneyTest(t *testing.T) {
	spec, err := campaign.LoadYAML([]byte(validTest))
	if err != nil {
		t.Fatal(err)
	}
	if string(spec.Cases[0].Value) != "-10" || len(spec.Cases[1].Value) != 0 || spec.Checks[0].Variable != "initial_balance" {
		t.Fatalf("spec=%#v", spec)
	}
	large := strings.Replace(validTest, "value: -10", "value: 9007199254740993", 1)
	spec, err = campaign.LoadYAML([]byte(large))
	if err != nil || string(spec.Cases[0].Value) != "9007199254740993" {
		t.Fatalf("number lost: %#v %v", spec, err)
	}
	null := strings.Replace(validTest, "value: -10", "value: null", 1)
	spec, err = campaign.LoadYAML([]byte(null))
	if err != nil || string(spec.Cases[0].Value) != "null" {
		t.Fatalf("null lost: %#v %v", spec, err)
	}
}

func TestRejectUnassessableDefinitions(t *testing.T) {
	cases := []string{
		strings.Replace(validTest, "observe_statuses: [201, 400, 422, 500]", "observe_statuses: []", 1),
		strings.Replace(validTest, "id: missing", "id: negative", 1),
		strings.Replace(validTest, "id: missing", "id: ../escape", 1),
		strings.Replace(validTest, "action: set", "action: unknown", 1),
		strings.Replace(validTest, "op: lte, variable: initial_balance", "op: eq, variable: initial_balance, value: 100", 1),
		strings.Replace(validTest, "op: lte, variable: initial_balance", "op: matches, value: '['", 1),
		strings.Replace(validTest, "action: remove", "action: remove, value: 1", 1),
		strings.Replace(validTest, "version: 1", "version: 1\nunknown: true", 1),
	}
	for _, source := range cases {
		if _, err := campaign.LoadYAML([]byte(source)); err == nil {
			t.Fatalf("invalid definition accepted:\n%s", source)
		}
	}
}
