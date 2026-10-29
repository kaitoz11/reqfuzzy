package capture_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/capture"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
)

func TestInferredPathDependencyReplaysFreshResponseValue(t *testing.T) {
	for _, tc := range []struct {
		name, captured, target, fresh, want string
	}{
		{"exact number", `{"id":123456}`, "/items/123456?keep=%2f", `{"id":9007199254740993}`, "/items/9007199254740993?keep=%2f"},
		{"decimal number", `{"id":123456.0}`, "/items/123456.0?keep=%2f", `{"id":9007199254740993.0}`, "/items/9007199254740993.0?keep=%2f"},
		{"exponent number", `{"id":1.23456e+5}`, "/items/1.23456e+5?keep=%2f", `{"id":9.007199254740993e+15}`, "/items/9.007199254740993e+15?keep=%2f"},
		{"encoded segment", `{"id":"old/id"}`, "/items/old%2fid?keep=%2f", `{"id":"fresh/id?"}`, "/items/fresh%2Fid%3F?keep=%2f"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			archive := capture.Capture{Exchanges: []capture.Exchange{
				{Name: "source", URL: "http://capture.test/source", RequestRaw: []byte("GET /source HTTP/1.1\r\nHost: capture.test\r\n\r\n"), ResponseStatus: 200, ResponseBodyPresent: true, ResponseBody: []byte(tc.captured)},
				{Name: "target", URL: "http://capture.test" + tc.target, RequestRaw: []byte("GET " + tc.target + " HTTP/1.1\r\nHost: capture.test\r\n\r\n"), ResponseStatus: 204},
			}}
			suggestion, err := capture.SuggestFlow(archive)
			if err != nil {
				t.Fatal(err)
			}
			if len(suggestion.Links) != 1 || suggestion.Links[0].ToLocation != "path" || suggestion.Links[0].ToPath != "1" || suggestion.Links[0].FromJSONPath != "id" {
				t.Fatalf("path links=%#v", suggestion.Links)
			}
			data, err := suggestion.YAML()
			if err != nil {
				t.Fatal(err)
			}
			definition, err := flow.LoadYAML(data)
			if err != nil {
				t.Fatal(err)
			}
			seen := make(chan string, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/source" {
					fmt.Fprint(w, tc.fresh)
					return
				}
				seen <- r.RequestURI
				w.WriteHeader(204)
			}))
			defer server.Close()
			paths, err := archive.WriteRequests(filepath.Join(t.TempDir(), "requests"))
			if err != nil {
				t.Fatal(err)
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
			if _, err := runner.Run(context.Background(), definition, nil); err != nil {
				t.Fatal(err)
			}
			if got := <-seen; got != tc.want {
				t.Fatalf("sent URI=%q want %q", got, tc.want)
			}
		})
	}
}

func TestPathInferenceLeavesAmbiguousAndShortIDsUnresolved(t *testing.T) {
	for _, tc := range []struct{ body, target string }{
		{`{"id":42}`, "/items/42"},
		{`{"a":123456,"b":123456}`, "/items/123456"},
		{`{"number":123456,"string":"123456"}`, "/items/123456"},
		{`{"id":"old/id"}`, "/items/old%252Fid"},
	} {
		archive := capture.Capture{Exchanges: []capture.Exchange{
			{Name: "source", URL: "http://capture.test/source", RequestRaw: []byte("GET /source HTTP/1.1\r\nHost: capture.test\r\n\r\n"), ResponseBodyPresent: true, ResponseBody: []byte(tc.body)},
			{Name: "target", URL: "http://capture.test" + tc.target, RequestRaw: []byte("GET " + tc.target + " HTTP/1.1\r\nHost: capture.test\r\n\r\n")},
		}}
		suggestion, err := capture.SuggestFlow(archive)
		if err != nil || len(suggestion.Links) != 0 {
			t.Fatalf("body=%s links=%#v err=%v", tc.body, suggestion.Links, err)
		}
	}
}
