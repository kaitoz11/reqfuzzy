package capture_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/capture"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
)

func TestInferredFormBindingSendsFreshValueAndPreservesOtherBytes(t *testing.T) {
	archive := capture.Capture{Exchanges: []capture.Exchange{
		{Name: "source", URL: "http://capture.test/source", RequestRaw: []byte("GET /source HTTP/1.1\r\nHost: capture.test\r\n\r\n"), ResponseStatus: 200, ResponseBodyPresent: true, ResponseBody: []byte(`{"csrf":"captured-123"}`)},
		{Name: "target", URL: "http://capture.test/submit", RequestRaw: []byte("POST /submit HTTP/1.1\r\nHost: capture.test\r\ncontent-type: application/x-www-form-urlencoded; charset=UTF-8\r\n\r\na=%2f&csrf=captured-123&z=hello%20world"), ResponseStatus: 204},
	}}
	suggestion, err := capture.SuggestFlow(archive)
	if err != nil || len(suggestion.Links) != 1 || suggestion.Links[0].ToLocation != "form" || suggestion.Links[0].ToPath != "csrf" {
		t.Fatalf("form links=%#v err=%v", suggestion.Links, err)
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
			fmt.Fprint(w, `{"csrf":"fresh-☃/a&=?+"}`)
			return
		}
		body, _ := io.ReadAll(r.Body)
		seen <- string(body)
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
	if got := <-seen; got != "a=%2f&csrf=fresh-%E2%98%83%2Fa%26%3D%3F%2B&z=hello%20world" {
		t.Fatalf("sent form=%q", got)
	}
}

func TestFormInferenceSkipsRepeatedFieldsAndInvalidFormEncoding(t *testing.T) {
	for _, tc := range []struct{ contentType, body string }{
		{"application/x-www-form-urlencoded", "id=captured-123&id=other"},
		{"application/x-www-form-urlencoded", "id=captured-123&bad=%ZZ"},
		{"text/plain", "id=captured-123"},
	} {
		archive := capture.Capture{Exchanges: []capture.Exchange{
			{Name: "source", URL: "http://capture.test/source", RequestRaw: []byte("GET /source HTTP/1.1\r\nHost: capture.test\r\n\r\n"), ResponseBodyPresent: true, ResponseBody: []byte(`{"id":"captured-123"}`)},
			{Name: "target", URL: "http://capture.test/target", RequestRaw: []byte("POST /target HTTP/1.1\r\nHost: capture.test\r\nContent-Type: " + tc.contentType + "\r\n\r\n" + tc.body)},
		}}
		suggestion, err := capture.SuggestFlow(archive)
		if err != nil || len(suggestion.Links) != 0 {
			t.Fatalf("body=%q links=%#v err=%v", tc.body, suggestion.Links, err)
		}
	}
}
