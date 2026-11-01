package cli_test

import (
	"fmt"
	"github.com/tidwall/gjson"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestRunAndComparePlanRepeatedVisitsBeforeAnyTraffic(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); fmt.Fprint(w, `{}`) }))
	defer server.Close()
	project := t.TempDir()
	write(t, filepath.Join(project, "project.yaml"), []byte("version: 1\norigin: "+server.URL+"\nrequests: {work: requests/work.txt}\n"))
	write(t, filepath.Join(project, "requests/work.txt"), []byte("GET /work HTTP/1.1\r\nX-Fuzz: base\r\n\r\n"))
	write(t, filepath.Join(project, "flow.yaml"), []byte("name: bounded\nsteps:\n  - {id: work, request: work, max_visits: 3, routes: [work], after_response: loop}\n"))
	write(t, filepath.Join(project, "hooks/loop.js"), []byte(`function afterResponse(ctx){if(ctx.flow.visit<3)ctx.flow.next("work");}`))
	for _, command := range []string{"run", "compare"} {
		base := []string{"flow", command, "--project", project, "--base-url", server.URL, "--json"}
		bound := "3"
		small := "2"
		want := int32(3)
		if command == "compare" {
			base = append(base, "--step", "work", "--location", "header", "--path", "X-Fuzz", "--value", "changed")
			bound = "6"
			small = "5"
			want = 6
		}
		before := calls.Load()
		code, out, stderr := call(append(append([]string(nil), base...), "--max-requests", small)...)
		if code != 1 || calls.Load() != before || !strings.Contains(out+stderr, "upper bound") {
			t.Fatalf("budget code=%d calls=%d out=%s err=%s", code, calls.Load()-before, out, stderr)
		}
		code, out, stderr = call(append(append([]string(nil), base...), "--max-requests", bound)...)
		if code != 0 || calls.Load()-before != want {
			t.Fatalf("allowed plan code=%d calls=%d out=%s err=%s", code, calls.Load()-before, out, stderr)
		}
	}
}

func TestFlowShowExposesStatusSetsAndVisitBounds(t *testing.T) {
	code, out, stderr := call("flow", "show", "--project", filepath.Join("..", "..", "examples", "session-recovery"), "--json")
	if code != 0 || gjson.Get(out, "result.steps.2.expect_statuses.#").Int() != 2 || gjson.Get(out, "result.steps.0.expect_status").Int() != 200 {
		t.Fatalf("status metadata missing code=%d out=%s err=%s", code, out, stderr)
	}
}
