package cli_test

import (
	"fmt"
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

func TestRecoveredJourneyRetainsMutationEvidenceAndReplay(t *testing.T) {
	for _, vulnerable := range []bool{false, true} {
		t.Run(fmt.Sprint(vulnerable), func(t *testing.T) {
			server := httptest.NewServer(reference.NewHandler(reference.Options{RefreshOnce: true, VulnerableAmounts: vulnerable}))
			defer server.Close()
			project := filepath.Join("..", "..", "examples", "session-recovery")
			run := filepath.Join(t.TempDir(), "run")
			code, out, stderr := call("flow", "test", "--project", project, "--base-url", server.URL, "--out", run, "--json")
			want := 0
			outcome := "pass"
			if vulnerable {
				want = 3
				outcome = "fail"
			}
			if code != want || stderr != "" || gjson.Get(out, "result.baseline.outcome").String() != "pass" || gjson.Get(out, "result.cases.0.outcome").String() != outcome || gjson.Get(out, "result.request_upper_bound").Int() != 21 {
				t.Fatalf("recovery code=%d out=%s err=%s", code, out, stderr)
			}
			artifact, err := os.ReadFile(filepath.Join(run, "negative.json"))
			if err != nil {
				t.Fatal(err)
			}
			if gjson.GetBytes(artifact, "flow.steps.#").Int() != 6 || gjson.GetBytes(artifact, "flow.steps.2.response.status").Int() != 401 || gjson.GetBytes(artifact, "flow.steps.2.next_step").String() != "refresh" || gjson.GetBytes(artifact, "flow.steps.5.visit").Int() != 2 || gjson.GetBytes(artifact, "trial.target_visit").Int() != 2 || gjson.GetBytes(artifact, "trial.mutation_proof").String() != "verified" {
				t.Fatal("recovery evidence lacks repeated response/decision metadata")
			}
			for _, index := range []string{"2", "5"} {
				if gjson.GetBytes(artifact, "flow.steps."+index+".sent.body.data.amount").Int() != -10 {
					t.Fatal("mutation was lost during recovery")
				}
			}
			if strings.Contains(string(artifact), "reference-token-") || strings.Contains(string(artifact), "reference-signing-") {
				t.Fatal("recovery evidence leaked credentials")
			}
			code, out, stderr = call("flow", "replay", "--project", project, "--base-url", server.URL, "--run", run, "--case", "negative", "--out", filepath.Join(t.TempDir(), "replay"), "--json")
			if code != want || stderr != "" || gjson.Get(out, "result.cases.0.target_visit").Int() != 2 {
				t.Fatalf("recovery replay code=%d out=%s err=%s", code, out, stderr)
			}
		})
	}
}

func TestRecoveryBudgetAndExhaustionCannotPass(t *testing.T) {
	var calls atomic.Int32
	handler := reference.NewHandler(reference.Options{RefreshOnce: true, ExpireAtTransfer: true})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); handler.ServeHTTP(w, r) }))
	defer server.Close()
	project := filepath.Join("..", "..", "examples", "session-recovery")
	code, out, stderr := call("flow", "test", "--project", project, "--base-url", server.URL, "--max-requests", "20", "--out", filepath.Join(t.TempDir(), "budget"), "--json")
	if code != 1 || calls.Load() != 0 {
		t.Fatalf("underplanned recovery sent traffic code=%d calls=%d out=%s err=%s", code, calls.Load(), out, stderr)
	}
	code, out, stderr = call("flow", "test", "--project", project, "--base-url", server.URL, "--out", filepath.Join(t.TempDir(), "exhausted"), "--json")
	if code != 2 || gjson.Get(out, "result.cases.#").Int() != 0 || gjson.Get(out, "result.baseline.error_kind").String() != "control" || calls.Load() != 6 {
		t.Fatalf("exhaustion code=%d calls=%d out=%s err=%s", code, calls.Load(), out, stderr)
	}
}
