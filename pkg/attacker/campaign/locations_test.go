package campaign_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/campaign"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
)

func TestPathAndFormMutationProofUsesTheSentMessage(t *testing.T) {
	for _, tc := range []struct{ name, location, path, action, value, raw string }{
		{"path set", "path", "1", "set", `"new/id"`, "GET /items/old/end HTTP/1.1\r\n\r\n"},
		{"path remove shifted segment", "path", "1", "remove", "", "GET /items/old/end HTTP/1.1\r\n\r\n"},
		{"form set", "form", "id", "set", `"changed"`, "POST /submit HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nid=base&keep=%2f"},
		{"form remove repeated fields", "form", "id", "remove", "", "POST /submit HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nid=base&id=other&keep=%2f"},
	} {
		for _, mode := range []string{"keep", "restore", "encoding"} {
			if mode == "encoding" && tc.location != "form" {
				continue
			}
			t.Run(fmt.Sprintf("%s/%s", tc.name, mode), func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					observed := r.URL.EscapedPath()
					if tc.location == "form" {
						body, _ := io.ReadAll(r.Body)
						observed = string(body)
					}
					json.NewEncoder(w).Encode(map[string]string{"observed": observed})
				}))
				defer server.Close()
				path := filepath.Join(t.TempDir(), "request.txt")
				if err := os.WriteFile(path, []byte(tc.raw), 0600); err != nil {
					t.Fatal(err)
				}
				store := attacker.NewRequestStore()
				store.RegisterRequestFilePath("send", path)
				status := 200
				main := flow.Flow{Name: "locations", Steps: []flow.Step{{ID: "send", Request: "send", ExpectStatus: &status, BeforeSend: "prepare"}}}
				runner := flow.Runner{Store: store, NewClient: func(string) (*attacker.HClient, error) {
					client := attacker.NewHClient()
					client.UseBaseURL(server.URL)
					return client, nil
				}, BeforeSend: map[string]flow.BeforeSend{"prepare": func(request attacker.Request, _ flow.Variables) error {
					if mode == "restore" {
						if tc.location == "path" {
							request.SetURL("/items/old/end")
						} else {
							_, body, _ := strings.Cut(tc.raw, "\r\n\r\n")
							request.SetBodyString(body)
						}
					}
					if mode == "encoding" {
						_, body, _ := strings.Cut(tc.raw, "\r\n\r\n")
						if string(request.Body) != body {
							request.SetHeaderNonCanonical("Content-Encoding", "gzip")
						}
					}
					return nil
				}}}
				spec := campaign.Spec{Version: 1, Name: "locations", Target: campaign.Target{Step: "send", Location: tc.location, Path: tc.path}, ObserveStatuses: []int{200}, Cases: []campaign.Case{{ID: "change", Action: tc.action, Value: campaign.Scalar(tc.value)}}, Checks: []campaign.Check{{ID: "same", Step: "send", Select: "json", Path: "observed", Op: "eq", Baseline: true}}}
				result, err := campaign.Run(context.Background(), runner, main, nil, spec, campaign.Options{})
				if err != nil || len(result.Cases) != 1 {
					t.Fatalf("result=%s cases=%d err=%v", result.Outcome, len(result.Cases), err)
				}
				want := campaign.Fail
				if mode != "keep" {
					want = campaign.Inconclusive
				}
				if result.Outcome != want || (mode == "keep" && result.Cases[0].MutationProof != "verified") || (mode == "encoding" && result.Cases[0].MutationProof != "unverified") {
					t.Fatalf("outcome=%s proof=%s want=%s", result.Outcome, result.Cases[0].MutationProof, want)
				}
			})
		}
	}
}

func TestNewMutationLocationsValidateStaticTargetsBeforeBaseline(t *testing.T) {
	for _, tc := range []struct{ location, path, raw string }{
		{"path", "8", "GET /items/old HTTP/1.1\r\n\r\n"},
		{"form", "id", "POST /submit HTTP/1.1\r\nContent-Type: text/plain\r\n\r\nid=base"},
		{"form", "id", "POST /submit HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nid=base&bad=%ZZ"},
	} {
		t.Run(tc.location+tc.path+tc.raw, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "request.txt")
			if err := os.WriteFile(path, []byte(tc.raw), 0600); err != nil {
				t.Fatal(err)
			}
			store := attacker.NewRequestStore()
			store.RegisterRequestFilePath("send", path)
			main := flow.Flow{Name: "preflight", Steps: []flow.Step{{ID: "send", Request: "send"}}}
			var clients atomic.Int32
			runner := flow.Runner{Store: store, NewClient: func(string) (*attacker.HClient, error) {
				clients.Add(1)
				return nil, fmt.Errorf("must fail before clients")
			}}
			spec := campaign.Spec{Version: 1, Name: "preflight", Target: campaign.Target{Step: "send", Location: tc.location, Path: tc.path}, ObserveStatuses: []int{200}, Cases: []campaign.Case{{ID: "change", Action: "set", Value: campaign.Scalar(`"changed"`)}}, Checks: []campaign.Check{{ID: "ok", Step: "send", Select: "status", Op: "eq", Value: campaign.Scalar("200")}}}
			if _, err := campaign.Run(context.Background(), runner, main, nil, spec, campaign.Options{}); err == nil || clients.Load() != 0 {
				t.Fatalf("static target was not rejected before baseline: err=%v clients=%d", err, clients.Load())
			}
		})
	}
}
