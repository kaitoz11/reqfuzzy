package campaign_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/campaign"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
)

func TestCookieMutationProofDetectsHookRestoration(t *testing.T) {
	for _, restore := range []bool{false, true} {
		t.Run(fmt.Sprint(restore), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/login" {
					http.SetCookie(w, &http.Cookie{Name: "sid", Value: "fresh", Path: "/"})
					fmt.Fprint(w, `{}`)
					return
				}
				value := ""
				if cookie, err := r.Cookie("sid"); err == nil {
					value = cookie.Value
				}
				json.NewEncoder(w).Encode(map[string]string{"sid": value})
			}))
			defer server.Close()
			store := attacker.NewRequestStore()
			for _, name := range []string{"login", "target"} {
				path := filepath.Join(t.TempDir(), name+".txt")
				if err := os.WriteFile(path, []byte("GET /"+name+" HTTP/1.1\r\n\r\n"), 0600); err != nil {
					t.Fatal(err)
				}
				store.RegisterRequestFilePath(name, path)
			}
			main := flow.Flow{Name: "cookie", Steps: []flow.Step{{ID: "login", Request: "login"}, {ID: "target", Request: "target", BeforeSend: "prepare"}}}
			runner := flow.Runner{Store: store, NewClient: func(string) (*attacker.HClient, error) {
				client := attacker.NewHClient()
				client.UseBaseURL(server.URL)
				return client, nil
			}, BeforeSend: map[string]flow.BeforeSend{"prepare": func(request attacker.Request, _ flow.Variables) error {
				if restore && request.Headers.Get("Cookie") != "" {
					request.SetHeaderNonCanonical("Cookie", "sid=fresh")
				}
				return nil
			}}}
			spec := campaign.Spec{Version: 1, Name: "cookie", Target: campaign.Target{Step: "target", Location: "cookie", Path: "sid"}, ObserveStatuses: []int{200}, Cases: []campaign.Case{{ID: "changed", Action: "set", Value: campaign.Scalar(`"changed"`)}}, Checks: []campaign.Check{{ID: "same", Step: "target", Select: "json", Path: "sid", Op: "eq", Baseline: true}}}
			result, err := campaign.Run(context.Background(), runner, main, nil, spec, campaign.Options{})
			if err != nil || len(result.Cases) != 1 {
				t.Fatalf("result=%s cases=%d err=%v", result.Outcome, len(result.Cases), err)
			}
			want := campaign.Fail
			if restore {
				want = campaign.Inconclusive
			}
			if result.Outcome != want || (!restore && result.Cases[0].MutationProof != "verified") {
				t.Fatalf("outcome=%s proof=%s want=%s", result.Outcome, result.Cases[0].MutationProof, want)
			}
		})
	}
}
