package flow_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
)

func TestResponseHookProvidesLaterBinding(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/login" {
			fmt.Fprint(w, `{"token":"runtime-token"}`)
			return
		}
		if r.Header.Get("Authorization") != "Bearer runtime-token" {
			http.Error(w, "missing token", 401)
			return
		}
		w.WriteHeader(204)
	}))
	defer server.Close()
	store := attacker.NewRequestStore()
	registerRawRequest(t, store, "login", "GET /login HTTP/1.1\r\nHost: capture.test\r\n\r\n")
	registerRawRequest(t, store, "use", "GET /use HTTP/1.1\r\nHost: capture.test\r\n\r\n")
	definition, err := flow.LoadYAML([]byte(`name: scripted
steps:
  - id: login
    request: login
    after_response: session
    provides: [token]
  - id: use
    request: use
    bind: [{location: header, path: Authorization, variable: token, prefix: "Bearer "}]
    expect_status: 204
`))
	if err != nil {
		t.Fatal(err)
	}
	runner := flow.Runner{Store: store, NewClient: func(string) (*attacker.HClient, error) {
		c := attacker.NewHClient()
		c.UseBaseURL(server.URL)
		return c, nil
	}, AfterResponse: map[string]flow.AfterResponse{"session": func(response attacker.Response, vars flow.Variables) error {
		v, err := flow.ParseValue([]byte(`"runtime-token"`))
		vars["token"] = v
		return err
	}}}
	result, err := runner.Run(context.Background(), definition, nil)
	if err != nil || hits.Load() != 2 || result.Steps[0].Extracted["token"].Text != "runtime-token" {
		t.Fatalf("result=%#v err=%v hits=%d", result, err, hits.Load())
	}
	runner.AfterResponse["session"] = func(attacker.Response, flow.Variables) error { return nil }
	result, err = runner.Run(context.Background(), definition, nil)
	var stepErr *flow.StepError
	if !errors.As(err, &stepErr) || stepErr.Kind != flow.ExtractionError || result.FailedStepID != "login" || hits.Load() != 3 {
		t.Fatalf("missing provided value: result=%#v err=%v hits=%d", result, err, hits.Load())
	}
}

func TestDeclaredScriptVariablesRequireResponseHook(t *testing.T) {
	_, err := flow.LoadYAML([]byte("name: bad\nsteps:\n  - id: one\n    request: one\n    provides: [token]\n"))
	if err == nil {
		t.Fatal("provides without after_response must fail")
	}
}

func TestSetMutationPreservesRawNumber(t *testing.T) {
	client := attacker.NewHClient()
	request, err := client.ParseRawRequest([]byte("POST / HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"id\":0}"))
	if err != nil {
		t.Fatal(err)
	}
	value, err := flow.ParseValue([]byte("9007199254740993"))
	if err != nil {
		t.Fatal(err)
	}
	mutate, err := flow.SetMutation("json", "id", value)
	if err != nil {
		t.Fatal(err)
	}
	if err := mutate(request, nil); err != nil || string(request.Body) != `{"id":9007199254740993}` {
		t.Fatalf("body=%s err=%v", request.Body, err)
	}
	if _, err := flow.ParseValue([]byte(`{"object":1}`)); err == nil {
		t.Fatal("non-scalar accepted")
	}
}
