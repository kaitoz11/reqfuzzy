package campaign_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/campaign"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
)

func TestRepeatedTargetUsesLastStatusAndProvesEveryMutation(t *testing.T) {
	for _, restore := range []bool{false, true} {
		t.Run(fmt.Sprint(restore), func(t *testing.T) {
			var sessions atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if _, err := r.Cookie("sid"); err != nil {
					http.SetCookie(w, &http.Cookie{Name: "sid", Value: fmt.Sprint(sessions.Add(1)), Path: "/"})
					w.WriteHeader(401)
					return
				}
				w.WriteHeader(200)
			}))
			defer server.Close()
			store := attacker.NewRequestStore()
			path := filepath.Join(t.TempDir(), "work.txt")
			if err := os.WriteFile(path, []byte("GET /work HTTP/1.1\r\nX-Fuzz: base\r\n\r\n"), 0600); err != nil {
				t.Fatal(err)
			}
			store.RegisterRequestFilePath("work", path)
			definition, err := flow.LoadYAML([]byte("name: repeat\nsteps:\n  - {id: work, request: work, max_visits: 2, expect_statuses: [200,401], routes: [work], before_send: prepare, after_response: decide}\n"))
			if err != nil {
				t.Fatal(err)
			}
			runner := flow.Runner{Store: store, NewClient: func(string) (*attacker.HClient, error) {
				c := attacker.NewHClient()
				c.UseBaseURL(server.URL)
				return c, nil
			}, BeforeSend: map[string]flow.BeforeSend{"prepare": func(request attacker.Request, _ flow.Variables) error {
				info, _ := flow.CurrentVisit(request.Context())
				if restore && info.Visit == 2 {
					request.SetHeaderNonCanonical("X-Fuzz", "base")
				}
				return nil
			}}, AfterResponse: map[string]flow.AfterResponse{"decide": func(response attacker.Response, _ flow.Variables) error {
				if response.StatusCode == 401 {
					return flow.SetNext(response.Request.Context(), "work")
				}
				return nil
			}}}
			spec, err := campaign.LoadYAML([]byte(`version: 1
name: repeats
target: {step: work, location: header, path: X-Fuzz}
observe_statuses: [200]
cases: [{id: changed, action: set, value: changed}]
checks:
  - {id: final, step: work, select: status, op: eq, value: 200, visit: last}
  - {id: initial-expiry, step: work, select: status, op: eq, value: 401, visit: 1}
  - {id: all-no-server-error, step: work, select: status, op: lt, value: 500, visit: all}
`))
			if err != nil {
				t.Fatal(err)
			}
			result, err := campaign.Run(context.Background(), runner, definition, nil, spec, campaign.Options{})
			if err != nil || len(result.Cases) != 1 {
				t.Fatalf("cases=%d err=%v", len(result.Cases), err)
			}
			want := campaign.Pass
			if restore {
				want = campaign.Inconclusive
			}
			if result.Outcome != want || result.Cases[0].TargetStatus != 200 {
				t.Fatalf("outcome=%s target=%d proof=%s", result.Outcome, result.Cases[0].TargetStatus, result.Cases[0].MutationProof)
			}
			if restore && result.Cases[0].MutationProof != "overwritten" {
				t.Fatalf("second visit was not checked: proof=%s", result.Cases[0].MutationProof)
			}
		})
	}
}

func TestAllVisitCheckCannotHideAnEarlierFailureOrMissingBaselineVisit(t *testing.T) {
	trial := campaign.Trial{Flow: flow.RunResult{Steps: []flow.StepResult{{StepID: "poll", Visit: 1, StatusCode: 500}, {StepID: "poll", Visit: 2, StatusCode: 200}}}}
	for _, tc := range []struct {
		visit string
		want  campaign.Outcome
	}{{"all", campaign.Fail}, {"last", campaign.Pass}, {"1", campaign.Fail}, {"3", campaign.Inconclusive}} {
		spec, err := campaign.LoadYAML([]byte("version: 1\nname: selectors\ntarget: {step: poll, location: header, path: X}\nobserve_statuses: [200]\ncases: [{id: x, action: set, value: x}]\nchecks: [{id: check, step: poll, select: status, op: lt, value: 500, visit: " + tc.visit + "}]\n"))
		if err != nil {
			t.Fatal(err)
		}
		if got := campaign.EvaluateCheck(spec.Checks[0], trial, trial); got.Outcome != tc.want {
			t.Fatalf("visit=%s outcome=%s want=%s", tc.visit, got.Outcome, tc.want)
		}
	}
	spec, err := campaign.LoadYAML([]byte("version: 1\nname: baseline\ntarget: {step: poll, location: header, path: X}\nobserve_statuses: [200]\ncases: [{id: x, action: set, value: x}]\nchecks: [{id: check, step: poll, select: status, op: eq, baseline: true, visit: all}]\n"))
	if err != nil {
		t.Fatal(err)
	}
	baseline := campaign.Trial{Flow: flow.RunResult{Steps: trial.Flow.Steps[:1]}}
	if got := campaign.EvaluateCheck(spec.Checks[0], trial, baseline); got.Outcome != campaign.Inconclusive {
		t.Fatalf("missing baseline visit became %s", got.Outcome)
	}
}
