package campaign_test

import (
	"encoding/base64"
	"runtime"
	"strings"
	"testing"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/campaign"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
	"github.com/tidwall/gjson"
)

func TestInlinePayloadsExpandTypedValuesAndExactRanges(t *testing.T) {
	spec, err := campaign.LoadYAML([]byte(`version: 1
name: reusable
target: {step: send, location: json, path: amount}
observe_statuses: [200]
cases: [{id: manual, action: set, value: 7}]
payloads:
  - {id: types, action: set, values: [-1, null, true, "-1", -1], unique: true}
  - {id: ids, action: set, range: {from: 9007199254740993, to: 9007199254740995}}
checks: [{id: ok, step: send, select: status, op: eq, value: 200}]
`))
	if err != nil {
		t.Fatal(err)
	}
	wantIDs := []string{"manual", "types-000001", "types-000002", "types-000003", "types-000004", "ids-000001", "ids-000002", "ids-000003"}
	wantValues := []string{"7", "-1", "null", "true", "\"-1\"", "9007199254740993", "9007199254740994", "9007199254740995"}
	if len(spec.Cases) != len(wantIDs) {
		t.Fatalf("cases=%d", len(spec.Cases))
	}
	for i, c := range spec.Cases {
		if c.ID != wantIDs[i] || string(c.Value) != wantValues[i] {
			t.Fatalf("case %d id=%s value=%s", i, c.ID, c.Value)
		}
	}
}

func payloadSpec(definition string) []byte {
	return []byte("version: 1\nname: payloads\ntarget: {step: send, location: json, path: value}\nobserve_statuses: [200]\npayloads:\n" + definition + "\nchecks: [{id: ok, step: send, select: status, op: eq, value: 200}]\n")
}

func TestPayloadLibraryAndFilesPreserveTypesAndLineSemantics(t *testing.T) {
	files := map[string][]byte{"payloads/library.yaml": []byte("version: 1\naction: set\nfile: numbers.jsonl\nformat: jsonl\n"), "payloads/numbers.jsonl": []byte("9007199254740993\nnull\n\"9007199254740993\"\n"), "words.txt": []byte("first\r\n\r\n{{value}}\r\n")}
	var reads []string
	spec, err := campaign.LoadYAMLWithResolver(payloadSpec("  - {id: numbers, use: payloads/library.yaml}\n  - {id: words, action: set, file: words.txt}"), func(name string) ([]byte, error) { reads = append(reads, name); return files[name], nil })
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(reads, ",") != "payloads/library.yaml,payloads/numbers.jsonl,words.txt" || len(spec.Cases) != 6 {
		t.Fatalf("reads=%v cases=%d", reads, len(spec.Cases))
	}
	for i, want := range []string{"9007199254740993", "null", "\"9007199254740993\"", "\"first\"", "\"\"", "\"{{value}}\""} {
		if string(spec.Cases[i].Value) != want {
			t.Fatalf("case%d=%s", i, spec.Cases[i].Value)
		}
	}
}

func TestPayloadDefinitionsRejectUnboundedOrAmbiguousSources(t *testing.T) {
	for _, definition := range []string{
		"  - {id: x, action: set, range: {from: 0, to: 10000}}",
		"  - {id: x, action: set, range: {from: 0, to: 2, step: 0}}",
		"  - {id: x, action: set, range: {from: 0, to: 2, step: null}}",
		"  - {id: x, action: set, range: {from: 0, to: 2, typo: 1}}",
		"  - {id: x, action: set, values: [1], file: words.txt}",
		"  - {id: x, action: set, values: []}",
		"  - {id: x, action: remove, values: [1]}",
		"  - {id: x, use: library.yaml, action: set}",
		"  - {id: x, action: set, values: [1], encode: [unknown]}",
		"  - {id: x, action: set, values: [1], encode: [null]}",
		"  - {id: x, action: set, values: [1], encode: null}",
	} {
		if _, err := campaign.LoadYAML(payloadSpec(definition)); err == nil {
			t.Fatalf("invalid payload definition accepted: %s", definition)
		}
	}
}

func TestRenderedCaseCompilationDoesNotRetainExpandedCopies(t *testing.T) {
	render := strings.Repeat("x", 64<<10)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	mutations := make([]flow.Mutation, 0, 1000)
	for i := 0; i < 1000; i++ {
		mutation, err := campaign.BuildCaseMutation(campaign.Target{Location: "json", Path: "value"}, campaign.Case{Action: "set", Render: render})
		if err != nil {
			t.Fatal(err)
		}
		mutations = append(mutations, mutation)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(mutations)
	if after.HeapAlloc > before.HeapAlloc+(32<<20) {
		t.Fatal("compiled cases retain duplicated rendered payloads")
	}
}

func TestPayloadTemplatesUseFreshBaseVariablesAndLiteralSubstitutions(t *testing.T) {
	mutation, err := campaign.BuildCaseMutation(campaign.Target{Location: "json", Path: "value"}, campaign.Case{Action: "set", Value: campaign.Scalar(`"{{var:secret}}"`), Render: "{{base}}|{{value}}|{{var:nonce}}", Encode: []string{"base64"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, base := range []string{"first", "second"} {
		request, err := attacker.NewHClient().ParseRawRequest([]byte("POST / HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"value\":\"" + base + "\"}"))
		if err != nil {
			t.Fatal(err)
		}
		value, _ := flow.ParseValue([]byte(`"fresh"`))
		if err := mutation(request, flow.Variables{"nonce": value}); err != nil {
			t.Fatal(err)
		}
		decoded, err := base64.StdEncoding.DecodeString(gjson.GetBytes(request.Body, "value").String())
		if err != nil || string(decoded) != base+"|{{var:secret}}|fresh" {
			t.Fatalf("rendered=%s err=%v", decoded, err)
		}
	}
}
