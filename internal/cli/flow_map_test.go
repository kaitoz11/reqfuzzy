package cli_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
	"github.com/tidwall/gjson"
	"gopkg.in/yaml.v3"
)

func mapPayload(t *testing.T, html []byte) map[string]any {
	t.Helper()
	matched := regexp.MustCompile(`(?s)<script id="project-data" type="application/json">(.*?)</script>`).FindSubmatch(html)
	if len(matched) != 2 {
		t.Fatal("map has no embedded project data")
	}
	var payload map[string]any
	if err := json.Unmarshal(matched[1], &payload); err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestFlowMapExportsPrivateOfflineEditorWithoutCapturedSecrets(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(500) }))
	defer server.Close()
	root := t.TempDir()
	input := filepath.Join(root, "capture.har")
	project := filepath.Join(root, "project")
	write(t, input, har(t, server.URL))
	if code, _, stderr := call("import", "--out", project, input); code != 0 {
		t.Fatal(stderr)
	}
	data, err := os.ReadFile(filepath.Join(project, "flow.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	definition, err := flow.LoadYAML(data)
	if err != nil {
		t.Fatal(err)
	}
	definition.Name = `Journey </script><img src=x onerror="globalThis.injected=true">`
	definition.Steps[0].BeforeSend = "loop"
	data, err = yaml.Marshal(definition)
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(project, "flow.yaml"), data)
	write(t, filepath.Join(project, "hooks", "loop.js"), []byte(`function beforeSend(ctx){while(true){} } // RAW_HOOK_SOURCE_SECRET`))
	output := filepath.Join(root, "maps", "journey.html")
	code, out, stderr := call("flow", "map", "--project", project, "--out", output, "--json")
	if code != 0 || stderr != "" {
		t.Fatalf("map code=%d out=%s err=%s", code, out, stderr)
	}
	if gjson.Get(out, "result.steps").Int() != 3 || gjson.Get(out, "result.dependencies").Int() != 2 {
		t.Fatalf("summary=%s", out)
	}
	html, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"captured-12345", "RAW_HOOK_SOURCE_SECRET", server.URL, `<img src=x onerror=`} {
		if strings.Contains(string(html), secret) {
			t.Fatalf("map contains source data or executable label %q", secret)
		}
	}
	payload := mapPayload(t, html)
	encoded, _ := json.Marshal(payload)
	if gjson.GetBytes(encoded, "flows.0.definition.name").String() != definition.Name {
		t.Fatal("hostile label was lost instead of escaped as data")
	}
	if hits.Load() != 0 {
		t.Fatalf("offline map sent %d requests", hits.Load())
	}
	info, err := os.Stat(output)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("private output mode=%v err=%v", info, err)
	}
	if code, _, _ := call("flow", "map", "--project", project, "--out", output); code != 1 {
		t.Fatalf("map overwrote existing output: code=%d", code)
	}
	unchanged, _ := os.ReadFile(output)
	if string(unchanged) != string(html) {
		t.Fatal("existing map changed")
	}
}

func TestFlowMapIncludesCampaignVerificationReferences(t *testing.T) {
	output := filepath.Join(t.TempDir(), "checkout.html")
	code, out, stderr := call("flow", "map", "--project", filepath.Join("..", "..", "examples", "juice-shop"), "--test", "tests.yaml", "--out", output, "--json")
	if code != 0 || stderr != "" {
		t.Fatalf("map code=%d out=%s err=%s", code, out, stderr)
	}
	html, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(mapPayload(t, html))
	if gjson.GetBytes(payload, "flows.#").Int() != 2 || gjson.GetBytes(payload, "flows.1.key").String() != "verify" || gjson.GetBytes(payload, "flows.1.definition.steps.0.bind.0.variable").String() != "token" {
		t.Fatalf("missing verification flow: %s", payload)
	}
	if gjson.GetBytes(payload, "campaign.target.step").String() != "update" || gjson.GetBytes(payload, "campaign.checks.0.phase").String() != "verify" {
		t.Fatal("missing campaign reference metadata")
	}
	if gjson.GetBytes(payload, "campaign.cases").Exists() || gjson.GetBytes(payload, "campaign.checks.0.value").Exists() {
		t.Fatal("map exported case/check operands")
	}
}
