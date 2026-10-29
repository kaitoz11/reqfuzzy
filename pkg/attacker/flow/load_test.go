package flow_test

import (
	"strings"
	"testing"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
)

const validFlowYAML = `name: item-journey
steps:
  - id: login
    request: login
    expect_status: 200
    extract:
      - name: token
        json: token
  - id: create
    request: create
    bind:
      - location: header
        path: Authorization
        variable: token
    before_send: sign
    expect_status: 201
    extract:
      - name: item_id
        json: id
  - id: read
    request: read
    bind:
      - location: query
        path: id
        variable: item_id
    expect_status: 200
`

func TestLoadYAMLPreservesStepOrderAndDefaultActor(t *testing.T) {
	got, err := flow.LoadYAML([]byte(validFlowYAML))
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "item-journey" || len(got.Steps) != 3 {
		t.Fatalf("flow = %#v", got)
	}
	for i, want := range []string{"login", "create", "read"} {
		if got.Steps[i].ID != want {
			t.Fatalf("step %d = %q, want %q", i, got.Steps[i].ID, want)
		}
		if got.Steps[i].Actor != "default" {
			t.Fatalf("step %s actor = %q, want default", want, got.Steps[i].Actor)
		}
	}
	if got.Steps[1].Bind[0].Variable != "token" || got.Steps[1].Bind[0].Location != "header" {
		t.Fatalf("create bindings = %#v", got.Steps[1].Bind)
	}
}

func TestLoadYAMLRejectsInvalidFlows(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{"empty flow", "name: x\nsteps: []\n", "at least one step"},
		{"duplicate step", "name: x\nsteps:\n  - {id: login, request: login}\n  - {id: login, request: again}\n", "duplicate id"},
		{"missing request", "name: x\nsteps:\n  - {id: login}\n", "request is required"},
		{"forward variable", "name: x\nsteps:\n  - id: use\n    request: use\n    bind: [{location: header, path: X-Token, variable: token}]\n  - id: login\n    request: login\n    extract: [{name: token, json: token}]\n", "earlier step"},
		{"invalid location", "name: x\nsteps:\n  - id: login\n    request: login\n    extract: [{name: token, json: token}]\n  - id: use\n    request: use\n    bind: [{location: unknown, path: sid, variable: token}]\n", "unsupported binding location"},
		{"prefix on JSON", "name: x\nsteps:\n  - id: source\n    request: source\n    extract: [{name: id, json: id}]\n  - id: target\n    request: target\n    bind: [{location: json, path: id, variable: id, prefix: x}]\n", "prefix"},
		{"duplicate variable", "name: x\nsteps:\n  - id: one\n    request: one\n    extract: [{name: token, json: token}]\n  - id: two\n    request: two\n    extract: [{name: token, json: token}]\n", "duplicate variable"},
		{"invalid status", "name: x\nsteps:\n  - {id: login, request: login, expect_status: 700}\n", "expect_status"},
		{"unknown field", "name: x\nsteps:\n  - {id: login, request: login, typo: true}\n", "field typo not found"},
		{"multiple documents", "name: x\nsteps:\n  - {id: login, request: login}\n---\nname: y\n", "exactly one YAML document"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := flow.LoadYAML([]byte(tc.yaml))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
	}
}
