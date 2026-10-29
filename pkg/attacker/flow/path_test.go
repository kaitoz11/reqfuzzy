package flow_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
)

func TestPathBindingEscapesOneSegmentAndPreservesTheRest(t *testing.T) {
	for _, tc := range []struct {
		name, value, prefix, want string
	}{
		{"reserved and unicode", "a/b?x#% ☃+", "", "/api%2fitems/a%2Fb%3Fx%23%25%20%E2%98%83+//?keep=%2f&q=a%20b"},
		{"prefix", "42", "item-", "/api%2fitems/item-42//?keep=%2f&q=a%20b"},
		{"dot", ".", "", "/api%2fitems/%2E//?keep=%2f&q=a%20b"},
		{"parent", "..", "", "/api%2fitems/%2E%2E//?keep=%2f&q=a%20b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seen := make(chan string, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/source" {
					json.NewEncoder(w).Encode(map[string]string{"id": tc.value})
					return
				}
				seen <- r.RequestURI
				w.WriteHeader(204)
			}))
			defer server.Close()
			store := attacker.NewRequestStore()
			registerRawRequest(t, store, "source", "GET /source HTTP/1.1\r\nHost: capture.test\r\n\r\n")
			registerRawRequest(t, store, "target", "GET /api%2fitems/stale//?keep=%2f&q=a%20b HTTP/1.1\r\nHost: capture.test\r\n\r\n")
			definition := flow.Flow{Name: "path", Steps: []flow.Step{
				{ID: "source", Request: "source", Extract: []flow.Extraction{{Name: "id", JSONPath: "id"}}},
				{ID: "target", Request: "target", Bind: []flow.Binding{{Location: "path", Path: "1", Variable: "id", Prefix: tc.prefix}}},
			}}
			runner := flow.Runner{Store: store, NewClient: func(string) (*attacker.HClient, error) {
				client := attacker.NewHClient()
				client.UseBaseURL(server.URL)
				return client, nil
			}}
			if _, err := runner.Run(context.Background(), definition, nil); err != nil {
				t.Fatal(err)
			}
			if got := <-seen; got != tc.want {
				t.Fatalf("sent URI=%q, want %q", got, tc.want)
			}
		})
	}
}

func TestPathBindingRejectsInvalidAddressBeforeCreatingClients(t *testing.T) {
	for _, index := range []string{"-1", "+1", "01", "1.0", "999999999999999999999999999", "2"} {
		t.Run(index, func(t *testing.T) {
			store := attacker.NewRequestStore()
			registerRawRequest(t, store, "source", "GET /source HTTP/1.1\r\nHost: capture.test\r\n\r\n")
			registerRawRequest(t, store, "target", "GET /items/stale HTTP/1.1\r\nHost: capture.test\r\n\r\n")
			definition := flow.Flow{Name: "invalid-path", Steps: []flow.Step{
				{ID: "source", Request: "source", Extract: []flow.Extraction{{Name: "id", JSONPath: "id"}}},
				{ID: "target", Request: "target", Bind: []flow.Binding{{Location: "path", Path: index, Variable: "id"}}},
			}}
			var clients atomic.Int32
			runner := flow.Runner{Store: store, NewClient: func(string) (*attacker.HClient, error) {
				clients.Add(1)
				return nil, fmt.Errorf("must fail before creating clients")
			}}
			if _, err := runner.Run(context.Background(), definition, nil); err == nil || clients.Load() != 0 {
				t.Fatalf("err=%v clients=%d", err, clients.Load())
			}
		})
	}
}

func TestFirstPathSegmentBindingKeepsTheTargetOrigin(t *testing.T) {
	for _, value := range []string{"@other.test", ""} {
		t.Run(value, func(t *testing.T) {
			var hits atomic.Int32
			seen := make(chan string, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				seen <- r.RequestURI
				w.WriteHeader(204)
			}))
			defer server.Close()
			store := attacker.NewRequestStore()
			registerRawRequest(t, store, "target", "GET /captured/items?q=x HTTP/1.1\r\nHost: capture.test\r\n\r\n")
			raw, _ := json.Marshal(value)
			variable, err := flow.ParseValue(raw)
			if err != nil {
				t.Fatal(err)
			}
			definition := flow.Flow{Name: "origin", Steps: []flow.Step{{ID: "target", Request: "target", Bind: []flow.Binding{{Location: "path", Path: "0", Variable: "id"}}}}}
			runner := flow.Runner{Store: store, InitialVariables: flow.Variables{"id": variable}, NewClient: func(string) (*attacker.HClient, error) {
				client := attacker.NewHClient()
				client.UseBaseURL(server.URL)
				return client, nil
			}}
			_, err = runner.Run(context.Background(), definition, nil)
			if value == "" {
				if err == nil || hits.Load() != 0 {
					t.Fatalf("empty first segment must be rejected before send: err=%v hits=%d", err, hits.Load())
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := <-seen; got != "/@other.test/items?q=x" {
				t.Fatalf("sent URI=%q", got)
			}
		})
	}
}
