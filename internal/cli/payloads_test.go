package cli_test

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kaitoz11/reqfuzzy/internal/reference"
	"github.com/tidwall/gjson"
)

func TestReusablePayloadPlanRunReplayAndSourceDrift(t *testing.T) {
	project := t.TempDir()
	if err := os.CopyFS(project, os.DirFS(filepath.Join("..", "..", "examples", "session-recovery"))); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(project, "payloads", "finance.yaml"), []byte("version: 1\naction: multiply\nfile: operators.jsonl\nformat: jsonl\n"))
	wordlist := filepath.Join(project, "payloads", "operators.jsonl")
	write(t, wordlist, []byte("-1\n0\n"))
	write(t, filepath.Join(project, "tests.yaml"), []byte(`version: 1
name: generated-finance
target: {step: transfer, location: json, path: amount}
observe_statuses: [201,422]
verify: verify.yaml
payloads: [{id: finance, use: payloads/finance.yaml}]
checks: [{id: balance, phase: verify, step: balance, select: json, path: balance, op: lte, variable: initial_balance}]
`))
	var calls atomic.Int32
	handler := reference.NewHandler(reference.Options{RefreshOnce: true, VulnerableAmounts: true})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); handler.ServeHTTP(w, r) }))
	defer server.Close()
	code, out, stderr := call("flow", "plan", "--project", project, "--max-requests", "20", "--json")
	if code != 0 || calls.Load() != 0 || gjson.Get(out, "result.request_upper_bound").Int() != 21 || gjson.Get(out, "result.within_budget").Bool() || gjson.Get(out, "result.cases.0.id").String() != "finance-000001" || gjson.Get(out, "result.cases.0.value").Exists() {
		t.Fatalf("plan code=%d calls=%d out=%s err=%s", code, calls.Load(), out, stderr)
	}
	run := filepath.Join(t.TempDir(), "run")
	code, out, stderr = call("flow", "test", "--project", project, "--base-url", server.URL, "--out", run, "--json")
	if code != 3 || gjson.Get(out, "result.cases.0.source").String() != "finance" || gjson.Get(out, "result.cases.0.target_visit").Int() != 2 {
		t.Fatalf("generated run code=%d out=%s err=%s", code, out, stderr)
	}
	code, out, stderr = call("flow", "replay", "--project", project, "--base-url", server.URL, "--run", run, "--case", "finance-000001", "--out", filepath.Join(t.TempDir(), "replay"), "--json")
	if code != 3 {
		t.Fatalf("generated replay code=%d out=%s err=%s", code, out, stderr)
	}
	before := calls.Load()
	write(t, wordlist, []byte("1\n0\n"))
	code, out, stderr = call("flow", "replay", "--project", project, "--base-url", server.URL, "--run", run, "--case", "finance-000001", "--out", filepath.Join(t.TempDir(), "drift"), "--json")
	if code != 1 || calls.Load() != before {
		t.Fatalf("source drift sent requests code=%d calls=%d out=%s err=%s", code, calls.Load()-before, out, stderr)
	}
}

func TestRuntimePayloadUsesNewNonceOnEveryRecoveryVisit(t *testing.T) {
	server := httptest.NewServer(reference.NewHandler(reference.Options{RefreshOnce: true}))
	defer server.Close()
	run := filepath.Join(t.TempDir(), "run")
	code, out, stderr := call("flow", "test", "--project", filepath.Join("..", "..", "examples", "session-recovery"), "--test", "text-payload-tests.yaml", "--base-url", server.URL, "--out", run, "--json")
	if code != 0 {
		t.Fatalf("text cases code=%d out=%s err=%s", code, out, stderr)
	}
	data, err := os.ReadFile(filepath.Join(run, "probes-000001.json"))
	if err != nil {
		t.Fatal(err)
	}
	var payloads []string
	for _, index := range []string{"2", "5"} {
		encoded := gjson.GetBytes(data, "flow.steps."+index+".sent.headers.X-Payload.0").String()
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		payloads = append(payloads, string(raw))
	}
	if payloads[0] == payloads[1] || !strings.HasPrefix(payloads[0], "probe:nonce-") || !strings.HasPrefix(payloads[1], "probe:nonce-") {
		t.Fatalf("payload state was stale: %q", payloads)
	}
}

func TestPayloadPlanningDoesNotExecuteHooksOrFollowExternalSymlinks(t *testing.T) {
	project := t.TempDir()
	if err := os.CopyFS(project, os.DirFS(filepath.Join("..", "..", "examples", "session-recovery"))); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(project, "hooks", "recover.js"), []byte(`while(true){}`))
	code, out, stderr := call("flow", "plan", "--project", project, "--test", "payload-tests.yaml", "--json")
	if code != 0 {
		t.Fatalf("planning executed hook code=%d out=%s err=%s", code, out, stderr)
	}
	external := filepath.Join(t.TempDir(), "operators.jsonl")
	write(t, external, []byte("-1\n"))
	inside := filepath.Join(project, "payloads", "operators.jsonl")
	if err := os.Remove(inside); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, inside); err != nil {
		t.Fatal(err)
	}
	code, out, stderr = call("flow", "plan", "--project", project, "--test", "payload-tests.yaml", "--json")
	if code != 1 {
		t.Fatalf("external payload symlink accepted code=%d out=%s err=%s", code, out, stderr)
	}
}
