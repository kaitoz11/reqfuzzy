package cli_test

import (
	"os"
	"strings"
	"testing"

	"github.com/dop251/goja"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
	"github.com/tidwall/gjson"
)

const mapCoreFixture = `{"format_version":1,"requests":["login","transfer","balance"],"flows":[
{"key":"flow","file":"flow.yaml","label":"Journey","definition":{"name":"journey","steps":[
{"id":"login","request":"login","after_response":"session","provides":["signed"],"extract":[{"name":"__proto__","cookie":"sid"},{"name":"balance","json":"balance"}]},
{"id":"transfer","request":"transfer","expect_status":201,"bind":[{"location":"cookie","path":"sid","variable":"__proto__"},{"location":"header","path":"X-Signed","variable":"signed"}]}]}},
{"key":"verify","file":"verify.yaml","label":"Verification","definition":{"name":"verify","steps":[
{"id":"login","request":"balance","expect_status":200,"bind":[{"location":"cookie","path":"sid","variable":"__proto__"}]}]}}
],"campaign":{"name":"balance","target":{"step":"transfer","location":"json","path":"amount"},"checks":[{"id":"no-increase","phase":"verify","step":"login","variable":"balance"}]}}`

func mapVM(t *testing.T) *goja.Runtime {
	t.Helper()
	source, err := os.ReadFile("flow_map_core.js")
	if err != nil {
		t.Fatal(err)
	}
	vm := goja.New()
	if err := vm.Set("projectText", mapCoreFixture); err != nil {
		t.Fatal(err)
	}
	if _, err := vm.RunString(string(source) + "\nvar project=JSON.parse(projectText);"); err != nil {
		t.Fatal(err)
	}
	return vm
}

func mapEval(t *testing.T, vm *goja.Runtime, expression string) string {
	t.Helper()
	value, err := vm.RunString(expression)
	if err != nil {
		t.Fatal(err)
	}
	return value.String()
}

func TestFlowMapCoreResolvesCrossPhaseCookieAndProvidedVariables(t *testing.T) {
	vm := mapVM(t)
	result := mapEval(t, vm, `var a=FlowMapCore.analyze(project); JSON.stringify({valid:a.valid,nodes:a.nodes.map(n=>n.key),edges:a.edges,errors:a.errors});`)
	if !gjson.Get(result, "valid").Bool() || gjson.Get(result, "edges.#").Int() != 3 || gjson.Get(result, "nodes.2").String() != "verify:0" {
		t.Fatalf("analysis=%s", result)
	}
	if gjson.Get(result, "edges.2.from").String() != "flow:0" || gjson.Get(result, "edges.2.to").String() != "verify:0" || gjson.Get(result, "edges.2.variable").String() != "__proto__" {
		t.Fatalf("cross-phase source=%s", result)
	}
}

func TestFlowMapCoreBlocksForwardAndCampaignReferenceBreaks(t *testing.T) {
	for _, edit := range []string{
		`project.flows[0].definition.steps.reverse();`,
		`project.flows[0].definition.steps.pop();`,
		`project.flows[0].definition.steps[0].extract[1].name="renamed";`,
		`delete project.flows[0].definition.steps[0].after_response;`,
	} {
		vm := mapVM(t)
		result := mapEval(t, vm, edit+`var blocked=false; try{FlowMapCore.exportFlow(project,"flow");}catch(e){blocked=true;} JSON.stringify({valid:FlowMapCore.analyze(project).valid,blocked});`)
		if gjson.Get(result, "valid").Bool() || !gjson.Get(result, "blocked").Bool() {
			t.Fatalf("broken edit exported: %s", result)
		}
	}
}

func TestFlowMapEditedExportRoundTripsExactStringsThroughGoLoader(t *testing.T) {
	vm := mapVM(t)
	name := "Journey </script><img>\u0085\u2028\u2029"
	if err := vm.Set("newName", name); err != nil {
		t.Fatal(err)
	}
	result := mapEval(t, vm, `project.flows[0].definition.name=newName; project.flows[0].definition.steps[1].bind[1].prefix="9007199254740993 "; FlowMapCore.exportFlow(project,"flow");`)
	definition, err := flow.LoadYAML([]byte(result))
	if err != nil {
		t.Fatal(err)
	}
	if definition.Name != name || definition.Steps[1].Bind[1].Prefix != "9007199254740993 " || *definition.Steps[1].ExpectStatus != 201 {
		t.Fatalf("export changed flow strings or status: name=%q", definition.Name)
	}
	if strings.Contains(result, "<img>") {
		t.Fatal("export contains executable markup when saved with an HTML filename")
	}
	verification := mapEval(t, vm, `FlowMapCore.exportFlow(project,"verify");`)
	seed, _ := flow.ParseValue([]byte(`"fresh"`))
	if _, err := flow.LoadYAMLWithVariables([]byte(verification), flow.Variables{"__proto__": seed}); err != nil {
		t.Fatal(err)
	}
}
