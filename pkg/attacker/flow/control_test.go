package flow_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/script"
)

func controlProgram(t *testing.T, source string) *script.Program {
	t.Helper()
	program, err := script.Compile("control", source, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return program
}

func TestScriptBranchRefreshesStateAndMutatesEveryVisit(t *testing.T) {
	seen := make(chan string, 8)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.URL.Path
		switch r.URL.Path {
		case "/session":
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "live", Path: "/"})
			fmt.Fprint(w, `{"token":"old"}`)
		case "/target":
			cookie, err := r.Cookie("sid")
			if err != nil || cookie.Value != "live" {
				http.Error(w, "session", 403)
				return
			}
			body, _ := io.ReadAll(r.Body)
			token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			mac := hmac.New(sha256.New, []byte(token))
			mac.Write(body)
			if r.Header.Get("X-Signature") != hex.EncodeToString(mac.Sum(nil)) {
				http.Error(w, "signature", 403)
				return
			}
			var payload struct {
				Amount int `json:"amount"`
			}
			json.Unmarshal(body, &payload)
			if payload.Amount != -10 {
				http.Error(w, "mutation lost", 400)
				return
			}
			if token == "old" {
				if r.Header.Get("X-Visit") != "1" {
					http.Error(w, "visit", 400)
					return
				}
				http.Error(w, "expired", 401)
				return
			}
			if token != "fresh" || r.Header.Get("X-Visit") != "2" {
				http.Error(w, "refresh", 403)
				return
			}
			fmt.Fprint(w, `{"id":7}`)
		case "/refresh":
			fmt.Fprint(w, `{"token":"fresh"}`)
		case "/done":
			if r.URL.Query().Get("id") != "7" {
				http.Error(w, "result", 400)
				return
			}
			w.WriteHeader(204)
		}
	}))
	defer server.Close()
	store := attacker.NewRequestStore()
	for _, name := range []string{"session", "refresh", "done"} {
		registerRawRequest(t, store, name, "GET /"+name+" HTTP/1.1\r\n\r\n")
	}
	registerRawRequest(t, store, "target", "POST /target HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"amount\":10}")
	definition, err := flow.LoadYAML([]byte(`name: refresh
steps:
  - {id: session, request: session, extract: [{name: token, json: token}]}
  - id: target
    request: target
    max_visits: 2
    expect_statuses: [200, 401]
    next: done
    routes: [refresh]
    bind: [{location: header, path: Authorization, prefix: "Bearer ", variable: token}]
    before_send: sign
    after_response: branch
    extract: [{name: txn_id, json: id, on_status: [200]}]
  - {id: refresh, request: refresh, next: target, after_response: refresh}
  - {id: done, request: done, expect_status: 204, bind: [{location: query, path: id, variable: txn_id}]}
`))
	if err != nil {
		t.Fatal(err)
	}
	sign := controlProgram(t, `function beforeSend(ctx){if(ctx.flow.step!=="target")throw new Error("step");ctx.request.setHeader("X-Visit",String(ctx.flow.visit));ctx.request.setHeader("X-Signature",crypto.hmacSha256(ctx.vars.get("token"),ctx.request.body));}`)
	branch := controlProgram(t, `function afterResponse(ctx){if(ctx.response.status===401)ctx.flow.next("refresh");}`)
	refresh := controlProgram(t, `function afterResponse(ctx){ctx.vars.set("token",JSON.parse(ctx.response.body).token);}`)
	runner := flow.Runner{Store: store, NewClient: func(string) (*attacker.HClient, error) {
		c := attacker.NewHClient()
		c.UseBaseURL(server.URL)
		return c, nil
	}, BeforeSend: map[string]flow.BeforeSend{"sign": sign.BeforeSend}, AfterResponse: map[string]flow.AfterResponse{"branch": branch.AfterResponse, "refresh": refresh.AfterResponse}}
	mutation, err := flow.BuildMutation(flow.MutationSpec{Action: "set", Location: "json", Path: "amount", Value: []byte("-10")})
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(context.Background(), definition, &flow.StepMutation{StepID: "target", Apply: mutation})
	if err != nil || len(result.Steps) != 5 || result.Variables["txn_id"].Text != "7" {
		t.Fatalf("steps=%d err=%v", len(result.Steps), err)
	}
	for _, want := range []string{"/session", "/target", "/refresh", "/target", "/done"} {
		if got := <-seen; got != want {
			t.Fatalf("request=%s want=%s", got, want)
		}
	}
}

func TestOptionalJSONExtractionRejectsMalformedOrAmbiguousData(t *testing.T) {
	for _, body := range []string{`not JSON`, `{"token":null,"token":"secret"}`, `{"token":{}}`} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
		store := attacker.NewRequestStore()
		registerRawRequest(t, store, "data", "GET / HTTP/1.1\r\n\r\n")
		definition, err := flow.LoadYAML([]byte("name: optional\nsteps:\n  - {id: data, request: data, extract: [{name: token, json: token, optional: true}]}\n"))
		if err != nil {
			t.Fatal(err)
		}
		runner := flow.Runner{Store: store, NewClient: func(string) (*attacker.HClient, error) {
			c := attacker.NewHClient()
			c.UseBaseURL(server.URL)
			return c, nil
		}}
		if _, err := runner.Run(context.Background(), definition, nil); err == nil {
			t.Fatal("optional extraction accepted invalid or ambiguous JSON")
		}
		server.Close()
	}
}

func TestPollingStopsAtReadyOrVisitLimitAndClearsOldOutputs(t *testing.T) {
	for _, mode := range []string{"ready", "limit", "stale-provided"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := calls.Add(1)
				if n == 1 {
					fmt.Fprint(w, `{"ready":false,"value":"old"}`)
				} else if n == 3 {
					fmt.Fprint(w, `{"ready":true,"value":"done"}`)
				} else {
					fmt.Fprint(w, `{"ready":false,"value":null}`)
				}
			}))
			defer server.Close()
			store := attacker.NewRequestStore()
			registerRawRequest(t, store, "poll", "GET /poll HTTP/1.1\r\n\r\n")
			provides := ""
			if mode == "stale-provided" {
				provides = "    provides: [provided]\n"
			}
			definition, err := flow.LoadYAML([]byte("name: polling\nsteps:\n  - id: poll\n    request: poll\n    max_visits: 3\n    routes: [poll]\n    after_response: decide\n    extract: [{name: value, json: value, optional: true}]\n" + provides))
			if err != nil {
				t.Fatal(err)
			}
			source := `function afterResponse(ctx){if(ctx.flow.visit===2){let missing=false;try{ctx.vars.get("value");}catch(e){missing=true;}if(!missing)throw new Error("stale optional output");}if(!JSON.parse(ctx.response.body).ready)ctx.flow.next("poll");}`
			if mode == "limit" {
				source = `function afterResponse(ctx){ctx.flow.next("poll");}`
			}
			if mode == "stale-provided" {
				source = `function afterResponse(ctx){if(ctx.flow.visit===1)ctx.vars.set("provided","first");ctx.flow.next("poll");}`
			}
			program := controlProgram(t, source)
			runner := flow.Runner{Store: store, NewClient: func(string) (*attacker.HClient, error) {
				c := attacker.NewHClient()
				c.UseBaseURL(server.URL)
				return c, nil
			}, AfterResponse: map[string]flow.AfterResponse{"decide": program.AfterResponse}}
			result, err := runner.Run(context.Background(), definition, nil)
			if mode == "ready" {
				if err != nil || calls.Load() != 3 || result.Variables["value"].Text != "done" {
					t.Fatalf("calls=%d err=%v", calls.Load(), err)
				}
			} else if mode == "limit" {
				if err == nil || calls.Load() != 3 {
					t.Fatalf("limit calls=%d err=%v", calls.Load(), err)
				}
			} else {
				if err == nil || calls.Load() != 2 {
					t.Fatalf("provided calls=%d err=%v", calls.Load(), err)
				}
				if _, exists := result.Variables["provided"]; exists {
					t.Fatal("stale provided output survived")
				}
			}
		})
	}
}

func TestSkippedMutationTargetCannotProduceSuccessfulRun(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(204) }))
	defer server.Close()
	store := attacker.NewRequestStore()
	registerRawRequest(t, store, "first", "GET /first HTTP/1.1\r\n\r\n")
	registerRawRequest(t, store, "target", "GET /target HTTP/1.1\r\n\r\n")
	definition, err := flow.LoadYAML([]byte("name: stop\nsteps:\n  - {id: first, request: first, next: \"\"}\n  - {id: target, request: target}\n"))
	if err != nil {
		t.Fatal(err)
	}
	runner := flow.Runner{Store: store, NewClient: func(string) (*attacker.HClient, error) {
		c := attacker.NewHClient()
		c.UseBaseURL(server.URL)
		return c, nil
	}}
	_, err = runner.Run(context.Background(), definition, &flow.StepMutation{StepID: "target", Apply: func(attacker.Request, flow.Variables) error { return nil }})
	if err == nil || calls.Load() != 1 {
		t.Fatalf("skipped target calls=%d err=%v", calls.Load(), err)
	}
}

func TestFailedResponseScriptDiscardsNavigationAndVariables(t *testing.T) {
	seen := make(chan string, 3)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen <- r.URL.Path; fmt.Fprint(w, `{}`) }))
	defer server.Close()
	store := attacker.NewRequestStore()
	for _, name := range []string{"first", "after", "jump"} {
		registerRawRequest(t, store, name, "GET /"+name+" HTTP/1.1\r\n\r\n")
	}
	definition, err := flow.LoadYAML([]byte("name: atomic\nsteps:\n  - {id: first, request: first, routes: [jump], after_response: fail}\n  - {id: after, request: after, next: \"\"}\n  - {id: jump, request: jump}\n"))
	if err != nil {
		t.Fatal(err)
	}
	program := controlProgram(t, `function afterResponse(ctx){ctx.vars.set("state","leaked");ctx.flow.next("jump");throw new Error("failed");}`)
	seed, _ := flow.ParseValue([]byte(`"safe"`))
	runner := flow.Runner{Store: store, InitialVariables: flow.Variables{"state": seed}, NewClient: func(string) (*attacker.HClient, error) {
		c := attacker.NewHClient()
		c.UseBaseURL(server.URL)
		return c, nil
	}, AfterResponse: map[string]flow.AfterResponse{"fail": func(response attacker.Response, values flow.Variables) error {
		if err := program.AfterResponse(response, values); err == nil {
			return fmt.Errorf("script did not fail")
		}
		return nil
	}}}
	result, err := runner.Run(context.Background(), definition, nil)
	if err != nil || len(result.Steps) != 2 || result.Variables["state"].Text != "safe" {
		t.Fatalf("atomic result steps=%d err=%v", len(result.Steps), err)
	}
	for _, want := range []string{"/first", "/after"} {
		if got := <-seen; got != want {
			t.Fatalf("failed script changed route to %s", got)
		}
	}
}

func TestControlDefinitionErrorsFailBeforeClientCreation(t *testing.T) {
	for _, fields := range []string{`max_visits: 0`, `max_visits: 1000001`, `next: missing`, `routes: [missing]`, `routes: [work, work]`, `expect_statuses: [200,200]`, `expect_statuses: []`} {
		if _, err := flow.LoadYAML([]byte("name: invalid\nsteps:\n  - {id: work, request: work, " + fields + "}\n")); err == nil {
			t.Fatalf("invalid control definition accepted: %s", fields)
		}
	}
}

func TestCompareRejectsSkippedBaselineBeforeMutatedRun(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); fmt.Fprint(w, `{}`) }))
	defer server.Close()
	store := attacker.NewRequestStore()
	for _, name := range []string{"first", "target"} {
		registerRawRequest(t, store, name, "GET /"+name+" HTTP/1.1\r\n\r\n")
	}
	definition, err := flow.LoadYAML([]byte("name: conditional\nsteps:\n  - {id: first, request: first, routes: [\"\"], after_response: decide}\n  - {id: target, request: target}\n"))
	if err != nil {
		t.Fatal(err)
	}
	runner := flow.Runner{Store: store, NewClient: func(string) (*attacker.HClient, error) {
		c := attacker.NewHClient()
		c.UseBaseURL(server.URL)
		return c, nil
	}, AfterResponse: map[string]flow.AfterResponse{"decide": func(response attacker.Response, _ flow.Variables) error {
		if calls.Load() == 1 {
			return flow.SetNext(response.Request.Context(), "")
		}
		return nil
	}}}
	_, err = runner.Compare(context.Background(), definition, flow.StepMutation{StepID: "target", Apply: func(attacker.Request, flow.Variables) error { return nil }})
	if err == nil || calls.Load() != 1 {
		t.Fatalf("comparison proceeded without baseline target: calls=%d err=%v", calls.Load(), err)
	}
}
