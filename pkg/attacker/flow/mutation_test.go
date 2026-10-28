package flow_test

import (
	"testing"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
)

func TestMorphingActionsChangeRealRequestBytes(t *testing.T) {
	cases := []struct{ name, action, location, path, value, raw, wantBody, wantURL string }{
		{"JSON null", "set", "json", "id", "null", "POST / HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"id\":1}", `{"id":null}`, "/"},
		{"JSON remove", "remove", "json", "id", "", "POST / HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"id\":1,\"keep\":2}", `{"keep":2}`, "/"},
		{"JSON append", "append", "json", "comment", `"-tail"`, "POST / HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"comment\":\"base\"}", `{"comment":"base-tail"}`, "/"},
		{"JSON prepend", "prepend", "json", "comment", `"head-"`, "POST / HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"comment\":\"base\"}", `{"comment":"head-base"}`, "/"},
		{"query remove", "remove", "query", "id", "", "GET /?a=%2F&id=one&z=hello%20world HTTP/1.1\r\n\r\n", "", "/?a=%2F&z=hello%20world"},
		{"query append", "append", "query", "id", `" tail"`, "GET /?a=%2F&id=base HTTP/1.1\r\n\r\n", "", "/?a=%2F&id=base+tail"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request, err := attacker.NewHClient().ParseRawRequest([]byte(tc.raw))
			if err != nil {
				t.Fatal(err)
			}
			mutation, err := flow.BuildMutation(flow.MutationSpec{Action: tc.action, Location: tc.location, Path: tc.path, Value: []byte(tc.value)})
			if err != nil {
				t.Fatal(err)
			}
			if err := mutation(request, nil); err != nil {
				t.Fatal(err)
			}
			if string(request.Body) != tc.wantBody || request.RawURL != tc.wantURL {
				t.Fatalf("body=%s url=%s", request.Body, request.RawURL)
			}
		})
	}
}

func TestMorphingRejectsAmbiguousOrWrongTypedAppend(t *testing.T) {
	cases := []struct{ location, path, raw string }{
		{"query", "id", "GET /?id=one&id=two HTTP/1.1\r\n\r\n"},
		{"header", "X-Token", "GET / HTTP/1.1\r\nX-Token: one\r\nx-token: two\r\n\r\n"},
		{"json", "id", "POST / HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"id\":1}"},
	}
	for _, tc := range cases {
		request, err := attacker.NewHClient().ParseRawRequest([]byte(tc.raw))
		if err != nil {
			t.Fatal(err)
		}
		mutation, err := flow.BuildMutation(flow.MutationSpec{Action: "append", Location: tc.location, Path: tc.path, Value: []byte(`"payload"`)})
		if err != nil {
			t.Fatal(err)
		}
		if err := mutation(request, nil); err == nil {
			t.Fatalf("ambiguous/wrong-typed mutation accepted: %s", tc.raw)
		}
	}
}

func TestRemoveRequiresExistingField(t *testing.T) {
	request, _ := attacker.NewHClient().ParseRawRequest([]byte("GET / HTTP/1.1\r\n\r\n"))
	mutation, err := flow.BuildMutation(flow.MutationSpec{Action: "remove", Location: "header", Path: "Missing"})
	if err != nil {
		t.Fatal(err)
	}
	if err := mutation(request, nil); err == nil {
		t.Fatal("no-op removal accepted")
	}
}
