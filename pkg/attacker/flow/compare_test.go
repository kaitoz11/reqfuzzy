package flow_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
)

func TestCompareReplaysFreshJourneyAndSignsChangedBody(t *testing.T) {
	var mu sync.Mutex
	loginCount := 0
	amounts := make(map[string]int)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			mu.Lock()
			loginCount++
			session := strconv.Itoa(loginCount)
			mu.Unlock()
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: session, Path: "/"})
			fmt.Fprintf(w, `{"token":"token-%s"}`, session)
		case "/create":
			cookie, err := r.Cookie("sid")
			if err != nil || r.Header.Get("Authorization") != "token-"+cookie.Value {
				http.Error(w, "session mismatch", http.StatusUnauthorized)
				return
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "body read failed", http.StatusBadRequest)
				return
			}
			sum := sha256.Sum256(body)
			if r.Header.Get("X-Body-Signature") != hex.EncodeToString(sum[:]) {
				http.Error(w, "signature mismatch", http.StatusUnauthorized)
				return
			}
			var payload struct {
				Amount int `json:"amount"`
			}
			if err := json.Unmarshal(body, &payload); err != nil {
				http.Error(w, "bad JSON", http.StatusBadRequest)
				return
			}
			mu.Lock()
			amounts[cookie.Value] = payload.Amount
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, `{"id":%s}`, cookie.Value)
		case "/read":
			cookie, err := r.Cookie("sid")
			if err != nil || r.URL.Query().Get("id") != cookie.Value {
				http.Error(w, "wrong session or item", http.StatusUnauthorized)
				return
			}
			mu.Lock()
			amount := amounts[cookie.Value]
			mu.Unlock()
			fmt.Fprintf(w, `{"amount":%d}`, amount)
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
	createdClients := 0
	runner := flow.Runner{
		Store: store,
		NewClient: func(string) (*attacker.HClient, error) {
			createdClients++
			client := attacker.NewHClient()
			client.UseBaseURL(server.URL)
			return client, nil
		},
		BeforeSend: map[string]flow.BeforeSend{
			"sign": func(request attacker.Request, variables flow.Variables) error {
				sum := sha256.Sum256(request.Body)
				request.SetHeader("X-Body-Signature", hex.EncodeToString(sum[:]))
				return nil
			},
		},
	}
	mutation := flow.StepMutation{StepID: "create", Apply: func(request attacker.Request, variables flow.Variables) error {
		if variables["token"].Text != "token-2" {
			return fmt.Errorf("second run token unavailable")
		}
		return request.UpdateJsonBody("amount", 99)
	}}
	comparison, err := runner.Compare(context.Background(), definition, mutation)
	if err != nil {
		t.Fatal(err)
	}
	if createdClients != 2 || loginCount != 2 {
		t.Fatalf("clients = %d, login sessions = %d; want two independent runs", createdClients, loginCount)
	}
	if len(comparison.Baseline.Steps) != 3 || len(comparison.Mutated.Steps) != 3 {
		t.Fatalf("comparison = %#v", comparison)
	}
	if string(comparison.Baseline.Steps[2].ResponseBody) != `{"amount":10}` || string(comparison.Mutated.Steps[2].ResponseBody) != `{"amount":99}` {
		t.Fatalf("downstream results: baseline=%s mutated=%s", comparison.Baseline.Steps[2].ResponseBody, comparison.Mutated.Steps[2].ResponseBody)
	}
	if string(comparison.Baseline.Steps[1].Request.Body) != `{"amount":10}` || string(comparison.Mutated.Steps[1].Request.Body) != `{"amount":99}` {
		t.Fatalf("prepared requests: baseline=%s mutated=%s", comparison.Baseline.Steps[1].Request.Body, comparison.Mutated.Steps[1].Request.Body)
	}
}

func TestCompareKeepsBaselineWhenMutatedStepFails(t *testing.T) {
	var creates atomic.Int32
	var reads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			fmt.Fprint(w, `{"token":"abc"}`)
		case "/create":
			if creates.Add(1) == 2 {
				w.WriteHeader(http.StatusConflict)
				return
			}
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"id":1}`)
		case "/read":
			reads.Add(1)
			fmt.Fprint(w, `{"amount":10}`)
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
	definition.Steps[1].BeforeSend = ""
	runner := flow.Runner{Store: store, NewClient: func(string) (*attacker.HClient, error) {
		client := attacker.NewHClient()
		client.UseBaseURL(server.URL)
		return client, nil
	}}
	mutation := flow.StepMutation{StepID: "create", Apply: func(request attacker.Request, _ flow.Variables) error {
		return request.UpdateJsonBody("amount", 99)
	}}
	comparison, err := runner.Compare(context.Background(), definition, mutation)
	var stepErr *flow.StepError
	if !errors.As(err, &stepErr) || stepErr.Kind != flow.StatusError || stepErr.StepID != "create" {
		t.Fatalf("error = %v, want changed create status error", err)
	}
	if len(comparison.Baseline.Steps) != 3 || len(comparison.Mutated.Steps) != 2 || comparison.Mutated.FailedStepID != "create" || reads.Load() != 1 {
		t.Fatalf("comparison = %#v, read requests = %d", comparison, reads.Load())
	}
}

func TestCompareRejectsUnknownMutationStepBeforeNetwork(t *testing.T) {
	var sent atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent.Add(1)
	}))
	defer server.Close()
	store := attacker.NewRequestStore()
	registerRawRequest(t, store, "one", "GET /one HTTP/1.1\r\nHost: example.test\r\n\r\n")
	runner := flow.Runner{Store: store, NewClient: func(string) (*attacker.HClient, error) {
		client := attacker.NewHClient()
		client.UseBaseURL(server.URL)
		return client, nil
	}}
	comparison, err := runner.Compare(context.Background(), flow.Flow{Name: "one", Steps: []flow.Step{{ID: "one", Request: "one"}}}, flow.StepMutation{StepID: "missing", Apply: func(attacker.Request, flow.Variables) error { return nil }})
	var stepErr *flow.StepError
	if !errors.As(err, &stepErr) || stepErr.Kind != flow.InvalidFlowError || sent.Load() != 0 || len(comparison.Baseline.Steps) != 0 {
		t.Fatalf("comparison = %#v, error = %v, requests sent = %d", comparison, err, sent.Load())
	}
}
