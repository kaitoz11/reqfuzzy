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

func TestHARCookieDependencyExtractsFreshSetCookie(t *testing.T) {
	archive, err := capture.ParseHAR([]byte(`{"log":{"version":"1.2","entries":[
{"request":{"method":"GET","url":"http://capture.test/login","headers":[]},"response":{"status":204,"headers":[{"name":"set-cookie","value":"sid=captured-123; Path=/; HttpOnly"}]}},
{"request":{"method":"GET","url":"http://capture.test/target","headers":[{"name":"Cookie","value":"sid=captured-123"}]},"response":{"status":204}}
]}}`))
	if err != nil {
		t.Fatal(err)
	}
	suggestion, err := capture.SuggestFlow(archive)
	if err != nil || len(suggestion.Links) != 1 || suggestion.Links[0].ToLocation != "cookie" || suggestion.Links[0].ToPath != "sid" {
		t.Fatalf("cookie links=%#v err=%v", suggestion.Links, err)
	}
	data, err := suggestion.YAML()
	if err != nil {
		t.Fatal(err)
	}
	definition, err := flow.LoadYAML(data)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan []string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "runtime-456", Path: "/"})
			w.WriteHeader(204)
			return
		}
		var values []string
		for _, cookie := range r.Cookies() {
			if cookie.Name == "sid" {
				values = append(values, cookie.Value)
			}
		}
		seen <- values
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
	if got := <-seen; len(got) != 1 || got[0] != "runtime-456" {
		t.Fatalf("runtime cookies=%q", got)
	}
}

func TestCookieInferenceSkipsDuplicateNamesAndRetainsLiteralPercentText(t *testing.T) {
	for _, tc := range []struct {
		body, cookie string
		links        int
	}{
		{`{"token":"literal%2F123"}`, "sid=literal%2F123", 1},
		{`{"token":"literal/123"}`, "sid=literal%2F123", 0},
		{`{"token":"captured-123"}`, "sid=captured-123; sid=other", 0},
		{`{"token":"captured-123"}`, "sid=captured-123; malformed", 0},
	} {
		archive := capture.Capture{Exchanges: []capture.Exchange{
			{Name: "source", URL: "http://capture.test/source", RequestRaw: []byte("GET /source HTTP/1.1\r\n\r\n"), ResponseBodyPresent: true, ResponseBody: []byte(tc.body)},
			{Name: "target", URL: "http://capture.test/target", RequestRaw: []byte(fmt.Sprintf("GET /target HTTP/1.1\r\nCookie: %s\r\n\r\n", tc.cookie))},
		}}
		suggestion, err := capture.SuggestFlow(archive)
		if err != nil || len(suggestion.Links) != tc.links {
			t.Fatalf("cookie links=%#v want=%d err=%v", suggestion.Links, tc.links, err)
		}
	}
}
