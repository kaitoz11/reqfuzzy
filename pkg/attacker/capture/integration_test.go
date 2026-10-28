package capture_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/capture"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
)

func TestHARToRunnerReplaysCurrentValues(t *testing.T) {
	var requestsSent atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestsSent.Add(1)
		switch r.URL.Path {
		case "/api/login":
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "runtime-session", Path: "/"})
			fmt.Fprint(w, `{"token":"runtime-token-999"}`)
		case "/api/transfer":
			cookie, err := r.Cookie("sid")
			if err != nil || cookie.Value != "runtime-session" || r.Header.Get("Authorization") != "Bearer runtime-token-999" {
				http.Error(w, "stale auth", http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"data":{"txnId":9007199254740995}}`)
		case "/api/confirm":
			var payload struct {
				TxnID json.Number `json:"txnId"`
			}
			decoder := json.NewDecoder(r.Body)
			decoder.UseNumber()
			if err := decoder.Decode(&payload); err != nil || payload.TxnID.String() != "9007199254740995" {
				http.Error(w, "stale transaction id", http.StatusBadRequest)
				return
			}
			fmt.Fprint(w, `{"confirmed":true}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	parsed, err := capture.ParseHAR(sampleHAR())
	if err != nil {
		t.Fatal(err)
	}
	paths, err := parsed.WriteRequests(filepath.Join(t.TempDir(), "requests"))
	if err != nil {
		t.Fatal(err)
	}
	suggestion, err := capture.SuggestFlow(parsed)
	if err != nil {
		t.Fatal(err)
	}
	yamlData, err := suggestion.YAML()
	if err != nil {
		t.Fatal(err)
	}
	definition, err := flow.LoadYAML(yamlData)
	if err != nil {
		t.Fatal(err)
	}
	if requestsSent.Load() != 0 {
		t.Fatal("offline import or inference sent a target request")
	}

	store := attacker.NewRequestStore()
	for name, path := range paths {
		store.RegisterRequestFilePath(name, path)
	}
	runner := flow.Runner{Store: store, NewClient: func(string) (*attacker.HClient, error) {
		client := attacker.NewHClient()
		client.UseBaseURL(server.URL)
		return client, nil
	}}
	result, err := runner.Run(context.Background(), definition, nil)
	if err != nil {
		t.Fatalf("inferred flow failed to replay: %v; result=%#v", err, result)
	}
	if requestsSent.Load() != 3 || len(result.Steps) != 3 || string(result.Steps[2].ResponseBody) != `{"confirmed":true}` {
		t.Fatalf("sent=%d result=%#v", requestsSent.Load(), result)
	}
}
