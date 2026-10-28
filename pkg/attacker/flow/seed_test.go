package flow_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
)

func TestSeededVerificationFlowKeepsValuesAndSentMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Evidence", "present")
		if r.URL.Path == "/login" {
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "fresh", Path: "/"})
			fmt.Fprint(w, `{}`)
			return
		}
		cookie, err := r.Cookie("sid")
		if err != nil || cookie.Value != "fresh" || r.Header.Get("Authorization") != "Bearer token-seed" {
			http.Error(w, "session", 401)
			return
		}
		fmt.Fprint(w, `{"balance":100}`)
	}))
	defer server.Close()
	store := attacker.NewRequestStore()
	registerRawRequest(t, store, "login", "GET /login HTTP/1.1\r\nHost: example.test\r\n\r\n")
	registerRawRequest(t, store, "balance", "GET /balance HTTP/1.1\r\nHost: example.test\r\n\r\n")
	token, _ := flow.ParseValue([]byte(`"token-seed"`))
	seed := flow.Variables{"token": token}
	definition, err := flow.LoadYAMLWithVariables([]byte("name: verify\nsteps:\n  - {id: login, request: login}\n  - id: balance\n    request: balance\n    bind: [{location: header, path: Authorization, variable: token, prefix: 'Bearer '}]\n    expect_status: 200\n"), seed)
	if err != nil {
		t.Fatal(err)
	}
	runner := flow.Runner{Store: store, InitialVariables: seed, NewClient: func(string) (*attacker.HClient, error) {
		c := attacker.NewHClient()
		c.UseBaseURL(server.URL)
		return c, nil
	}}
	result, err := runner.Run(context.Background(), definition, nil)
	if err != nil {
		t.Fatal(err)
	}
	sent := result.Steps[1].SentRequest
	if sent == nil || sent.RawURL != server.URL+"/balance" || sent.Headers.Get("Cookie") == "" || result.Steps[1].ResponseHeaders.Get("X-Evidence") != "present" {
		t.Fatalf("incomplete HTTP evidence: %#v", result.Steps[1])
	}
	result.Variables["token"].RawJSON[0] = 'x'
	if string(seed["token"].RawJSON) != `"token-seed"` {
		t.Fatal("run mutated the seed")
	}
}

func TestSeededFlowPreflightDoesNotCreateClients(t *testing.T) {
	store := attacker.NewRequestStore()
	registerRawRequest(t, store, "one", "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
	calls := 0
	runner := flow.Runner{Store: store, NewClient: func(string) (*attacker.HClient, error) { calls++; return attacker.NewHClient(), nil }}
	if err := runner.Preflight(flow.Flow{Name: "one", Steps: []flow.Step{{ID: "one", Request: "one"}}}); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("preflight created a session")
	}
}
