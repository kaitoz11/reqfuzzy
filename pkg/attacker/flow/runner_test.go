package flow_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
)

func registerRawRequest(t *testing.T, store *attacker.RequestStore, name, raw string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), name+".txt")
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	store.RegisterRequestFilePath(name, path)
}

func TestRunnerBindsLargeJSONNumberWithoutPrecisionLoss(t *testing.T) {
	const largeID = "9007199254740993"
	var sentBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/source" {
			fmt.Fprintf(w, `{"id":%s}`, largeID)
			return
		}
		body, _ := io.ReadAll(r.Body)
		sentBody = string(body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	store := attacker.NewRequestStore()
	registerRawRequest(t, store, "source", "GET /source HTTP/1.1\r\nHost: example.test\r\n\r\n")
	registerRawRequest(t, store, "target", "POST /target HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\n\r\n{\"id\":0}")
	definition := flow.Flow{Name: "large-id", Steps: []flow.Step{
		{ID: "source", Request: "source", Extract: []flow.Extraction{{Name: "id", JSONPath: "id"}}},
		{ID: "target", Request: "target", Bind: []flow.Binding{{Location: "json", Path: "id", Variable: "id"}}},
	}}
	runner := flow.Runner{Store: store, NewClient: func(string) (*attacker.HClient, error) {
		client := attacker.NewHClient()
		client.UseBaseURL(server.URL)
		return client, nil
	}}
	if _, err := runner.Run(context.Background(), definition, nil); err != nil {
		t.Fatal(err)
	}
	if sentBody != `{"id":`+largeID+`}` {
		t.Fatalf("body = %q, want exact large JSON number", sentBody)
	}
}

func TestRunnerPreflightsMissingRequestBeforeSending(t *testing.T) {
	var sent atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	store := attacker.NewRequestStore()
	registerRawRequest(t, store, "present", "GET /present HTTP/1.1\r\nHost: example.test\r\n\r\n")
	definition := flow.Flow{Name: "preflight", Steps: []flow.Step{{ID: "first", Request: "present"}, {ID: "second", Request: "missing"}}}
	runner := flow.Runner{Store: store, NewClient: func(string) (*attacker.HClient, error) {
		client := attacker.NewHClient()
		client.UseBaseURL(server.URL)
		return client, nil
	}}
	_, err := runner.Run(context.Background(), definition, nil)
	var stepErr *flow.StepError
	if !errors.As(err, &stepErr) || stepErr.StepID != "second" || stepErr.Kind != flow.RequestError {
		t.Fatalf("error = %v, want missing request at second step", err)
	}
	if sent.Load() != 0 {
		t.Fatalf("sent %d requests before preflight completed", sent.Load())
	}
}

func TestRunnerStopsOnStatusAndKeepsTrace(t *testing.T) {
	var sent atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent.Add(1)
		w.WriteHeader(http.StatusConflict)
	}))
	defer server.Close()
	store := attacker.NewRequestStore()
	registerRawRequest(t, store, "one", "GET /one HTTP/1.1\r\nHost: example.test\r\n\r\n")
	registerRawRequest(t, store, "two", "GET /two HTTP/1.1\r\nHost: example.test\r\n\r\n")
	status := http.StatusOK
	definition := flow.Flow{Name: "failure", Steps: []flow.Step{{ID: "first", Request: "one", ExpectStatus: &status}, {ID: "second", Request: "two"}}}
	runner := flow.Runner{Store: store, NewClient: func(string) (*attacker.HClient, error) {
		client := attacker.NewHClient()
		client.UseBaseURL(server.URL)
		return client, nil
	}}
	result, err := runner.Run(context.Background(), definition, nil)
	var stepErr *flow.StepError
	if !errors.As(err, &stepErr) || stepErr.Kind != flow.StatusError || stepErr.StepID != "first" {
		t.Fatalf("error = %v, want status error at first step", err)
	}
	if result.FailedStepID != "first" || len(result.Steps) != 1 || result.Steps[0].StatusCode != http.StatusConflict || sent.Load() != 1 {
		t.Fatalf("result = %#v, requests sent = %d", result, sent.Load())
	}
}

func TestRunnerHookErrorPreventsSend(t *testing.T) {
	var sent atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent.Add(1)
	}))
	defer server.Close()
	store := attacker.NewRequestStore()
	registerRawRequest(t, store, "one", "GET /one HTTP/1.1\r\nHost: example.test\r\n\r\n")
	definition := flow.Flow{Name: "hook", Steps: []flow.Step{{ID: "one", Request: "one", BeforeSend: "sign"}}}
	runner := flow.Runner{Store: store, NewClient: func(string) (*attacker.HClient, error) {
		client := attacker.NewHClient()
		client.UseBaseURL(server.URL)
		return client, nil
	}, BeforeSend: map[string]flow.BeforeSend{"sign": func(attacker.Request, flow.Variables) error {
		return fmt.Errorf("cannot sign")
	}}}
	result, err := runner.Run(context.Background(), definition, nil)
	var stepErr *flow.StepError
	if !errors.As(err, &stepErr) || stepErr.Kind != flow.HookError || stepErr.StepID != "one" {
		t.Fatalf("error = %v, want hook error", err)
	}
	if sent.Load() != 0 || result.FailedStepID != "one" {
		t.Fatalf("request sent = %d, result = %#v", sent.Load(), result)
	}
}

func TestRunnerRejectsJSONBindingIntoPlainBody(t *testing.T) {
	var targetSent atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/source" {
			fmt.Fprint(w, `{"id":5}`)
			return
		}
		targetSent.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	store := attacker.NewRequestStore()
	registerRawRequest(t, store, "source", "GET /source HTTP/1.1\r\nHost: example.test\r\n\r\n")
	registerRawRequest(t, store, "target", "POST /target HTTP/1.1\r\nHost: example.test\r\nContent-Type: text/plain\r\n\r\nplain")
	definition := flow.Flow{Name: "bad-body", Steps: []flow.Step{
		{ID: "source", Request: "source", Extract: []flow.Extraction{{Name: "id", JSONPath: "id"}}},
		{ID: "target", Request: "target", Bind: []flow.Binding{{Location: "json", Path: "id", Variable: "id"}}},
	}}
	runner := flow.Runner{Store: store, NewClient: func(string) (*attacker.HClient, error) {
		client := attacker.NewHClient()
		client.UseBaseURL(server.URL)
		return client, nil
	}}
	result, err := runner.Run(context.Background(), definition, nil)
	var stepErr *flow.StepError
	if !errors.As(err, &stepErr) || stepErr.Kind != flow.BindingError || stepErr.StepID != "target" {
		t.Fatalf("error = %v, want JSON binding error", err)
	}
	if targetSent.Load() != 0 || len(result.Steps) != 1 {
		t.Fatalf("target sent = %d, result = %#v", targetSent.Load(), result)
	}
}

func TestRunnerStopsWhenExtractionIsMissing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{}`)
	}))
	defer server.Close()
	store := attacker.NewRequestStore()
	registerRawRequest(t, store, "source", "GET /source HTTP/1.1\r\nHost: example.test\r\n\r\n")
	definition := flow.Flow{Name: "missing-value", Steps: []flow.Step{{ID: "source", Request: "source", Extract: []flow.Extraction{{Name: "id", JSONPath: "id"}}}}}
	runner := flow.Runner{Store: store, NewClient: func(string) (*attacker.HClient, error) {
		client := attacker.NewHClient()
		client.UseBaseURL(server.URL)
		return client, nil
	}}
	result, err := runner.Run(context.Background(), definition, nil)
	var stepErr *flow.StepError
	if !errors.As(err, &stepErr) || stepErr.Kind != flow.ExtractionError || stepErr.StepID != "source" {
		t.Fatalf("error = %v, want source extraction error", err)
	}
	if len(result.Steps) != 1 || result.Steps[0].StatusCode != http.StatusOK || result.FailedStepID != "source" {
		t.Fatalf("partial result = %#v", result)
	}
}

func TestRunnerCanceledContextPreventsSend(t *testing.T) {
	var sent atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent.Add(1)
	}))
	defer server.Close()
	store := attacker.NewRequestStore()
	registerRawRequest(t, store, "one", "GET /one HTTP/1.1\r\nHost: example.test\r\n\r\n")
	definition := flow.Flow{Name: "cancel", Steps: []flow.Step{{ID: "one", Request: "one"}}}
	runner := flow.Runner{Store: store, NewClient: func(string) (*attacker.HClient, error) {
		client := attacker.NewHClient()
		client.UseBaseURL(server.URL)
		return client, nil
	}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := runner.Run(ctx, definition, nil)
	if !errors.Is(err, context.Canceled) || result.FailedStepID != "one" || sent.Load() != 0 {
		t.Fatalf("result = %#v, error = %v, requests sent = %d", result, err, sent.Load())
	}
}

func TestRunnerTransportErrorKeepsEarlierTrace(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/drop" {
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			_ = connection.Close()
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	store := attacker.NewRequestStore()
	registerRawRequest(t, store, "one", "GET /one HTTP/1.1\r\nHost: example.test\r\n\r\n")
	registerRawRequest(t, store, "drop", "GET /drop HTTP/1.1\r\nHost: example.test\r\n\r\n")
	definition := flow.Flow{Name: "transport", Steps: []flow.Step{{ID: "one", Request: "one"}, {ID: "drop", Request: "drop"}}}
	runner := flow.Runner{Store: store, NewClient: func(string) (*attacker.HClient, error) {
		client := attacker.NewHClient()
		client.UseBaseURL(server.URL)
		return client, nil
	}}
	result, err := runner.Run(context.Background(), definition, nil)
	var stepErr *flow.StepError
	if !errors.As(err, &stepErr) || stepErr.Kind != flow.TransportError || stepErr.StepID != "drop" {
		t.Fatalf("error = %v, want transport error at drop", err)
	}
	if len(result.Steps) != 2 || result.Steps[0].StatusCode != http.StatusOK || result.Steps[1].StatusCode != 0 {
		t.Fatalf("partial trace = %#v", result.Steps)
	}
}

func TestRunnerCarriesStateAcrossNamedRequests(t *testing.T) {
	const largeID = "9007199254740993"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "session-1", Path: "/"})
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"token":"abc"}`)
		case "/create":
			cookie, err := r.Cookie("sid")
			if err != nil || cookie.Value != "session-1" || r.Header.Get("Authorization") != "abc" || r.Header.Get("X-Prepared") != "yes" {
				http.Error(w, "missing session, token, or hook", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, `{"id":%s}`, largeID)
		case "/read":
			if r.URL.Query().Get("id") != largeID {
				http.Error(w, "wrong item id", http.StatusBadRequest)
				return
			}
			cookie, err := r.Cookie("sid")
			if err != nil || cookie.Value != "session-1" {
				http.Error(w, "missing session", http.StatusUnauthorized)
				return
			}
			fmt.Fprint(w, `{"amount":10}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	store := attacker.NewRequestStore()
	registerRawRequest(t, store, "login", "GET /login HTTP/1.1\r\nHost: example.test\r\n\r\n")
	registerRawRequest(t, store, "create", "POST /create HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\n\r\n{\"amount\":10}")
	registerRawRequest(t, store, "read", "GET /read HTTP/1.1\r\nHost: example.test\r\n\r\n")

	definition, err := flow.LoadYAML([]byte(validFlowYAML))
	if err != nil {
		t.Fatal(err)
	}
	runner := flow.Runner{
		Store: store,
		NewClient: func(actor string) (*attacker.HClient, error) {
			if actor != "default" {
				return nil, fmt.Errorf("unexpected actor %q", actor)
			}
			client := attacker.NewHClient()
			client.UseBaseURL(server.URL)
			return client, nil
		},
		BeforeSend: map[string]flow.BeforeSend{
			"sign": func(request attacker.Request, variables flow.Variables) error {
				if variables["token"].Text != "abc" {
					return fmt.Errorf("token not available to hook")
				}
				request.SetHeader("X-Prepared", "yes")
				return nil
			},
		},
	}
	result, err := runner.Run(context.Background(), definition, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Steps) != 3 || result.Steps[0].StepID != "login" || result.Steps[1].StatusCode != 201 || result.Steps[2].StatusCode != 200 {
		t.Fatalf("unexpected step results: %#v", result.Steps)
	}
	if got := string(result.Variables["item_id"].RawJSON); got != largeID {
		t.Fatalf("item_id raw JSON = %q, want %q", got, largeID)
	}
}
