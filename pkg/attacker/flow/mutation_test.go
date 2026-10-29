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
		{"array remove first", "remove", "json", "items.0", "", "POST / HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"items\":[10,20]}", `{"items":[20]}`, "/"},
		{"root array remove first", "remove", "json", "0", "", "POST / HTTP/1.1\r\nContent-Type: application/json\r\n\r\n[10,20]", `[20]`, "/"},
		{"JSON append", "append", "json", "comment", `"-tail"`, "POST / HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"comment\":\"base\"}", `{"comment":"base-tail"}`, "/"},
		{"JSON prepend", "prepend", "json", "comment", `"head-"`, "POST / HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"comment\":\"base\"}", `{"comment":"head-base"}`, "/"},
		{"query remove", "remove", "query", "id", "", "GET /?a=%2F&id=one&z=hello%20world HTTP/1.1\r\n\r\n", "", "/?a=%2F&z=hello%20world"},
		{"query append", "append", "query", "id", `" tail"`, "GET /?a=%2F&id=base HTTP/1.1\r\n\r\n", "", "/?a=%2F&id=base+tail"},
		{"path set", "set", "path", "1", `"new/id?x#"`, "GET /items/old/end?keep=%2f HTTP/1.1\r\n\r\n", "", "/items/new%2Fid%3Fx%23/end?keep=%2f"},
		{"path remove", "remove", "path", "1", "", "GET /items/old/end?keep=%2f HTTP/1.1\r\n\r\n", "", "/items/end?keep=%2f"},
		{"path append", "append", "path", "1", `"/tail"`, "GET /items/base?keep=%2f HTTP/1.1\r\n\r\n", "", "/items/base%2Ftail?keep=%2f"},
		{"path prepend", "prepend", "path", "1", `"head/"`, "GET /items/base HTTP/1.1\r\n\r\n", "", "/items/head%2Fbase"},
		{"form set repeated", "set", "form", "id", `"new/id"`, "POST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\na=%2f&%69d=one&id=two&z=hello%20world", "a=%2f&%69d=new%2Fid&z=hello%20world", "/"},
		{"form remove repeated", "remove", "form", "id", "", "POST / HTTP/1.1\r\ncontent-type: application/x-www-form-urlencoded; charset=UTF-8\r\n\r\na=%2f&id=one&id=two&z=hello%20world", "a=%2f&z=hello%20world", "/"},
		{"form append", "append", "form", "id", `" tail"`, "POST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\na=%2f&id=base", "a=%2f&id=base+tail", "/"},
		{"form prepend", "prepend", "form", "id", `"head&"`, "POST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nid=base", "id=head%26base", "/"},
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
		{"form", "id", "POST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nid=one&id=two"},
		{"form", "id", "POST / HTTP/1.1\r\nContent-Type: text/plain\r\n\r\nid=one"},
		{"form", "id", "POST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nid=one&bad=%ZZ"},
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

func TestJSONMutationRejectsDuplicateMembersAndAncestors(t *testing.T) {
	for _, body := range []string{`{"name":"one","name":"two"}`, `{"outer":{"name":"one"},"outer":{"name":"two"}}`} {
		path := "name"
		if body[2] == 'o' {
			path = "outer.name"
		}
		for _, action := range []string{"set", "remove", "append", "prepend"} {
			request, _ := attacker.NewHClient().ParseRawRequest([]byte("POST / HTTP/1.1\r\nContent-Type: application/json\r\n\r\n" + body))
			var value []byte
			if action != "remove" {
				value = []byte(`"changed"`)
			}
			mutation, err := flow.BuildMutation(flow.MutationSpec{Action: action, Location: "json", Path: path, Value: value})
			if err != nil {
				t.Fatal(err)
			}
			if err := mutation(request, nil); err == nil {
				t.Fatalf("%s accepted ambiguous JSON: %s", action, body)
			}
		}
	}
}

func TestNormalHTTPMutationRejectsManagedFramingAndHostRemoval(t *testing.T) {
	for _, spec := range []flow.MutationSpec{{Action: "remove", Location: "header", Path: "Host"}, {Action: "set", Location: "header", Path: "Content-Length", Value: []byte(`"0"`)}, {Action: "remove", Location: "header", Path: "Transfer-Encoding"}} {
		if _, err := flow.BuildMutation(spec); err == nil {
			t.Fatalf("unsupported transport-managed mutation accepted: %#v", spec)
		}
	}
}

func TestMutationRejectsUnsupportedSelectorSyntax(t *testing.T) {
	for _, path := range []string{"items|0.amount", "items.#.amount", "items.@this.amount"} {
		if _, err := flow.BuildMutation(flow.MutationSpec{Action: "set", Location: "json", Path: path, Value: []byte("-10")}); err == nil {
			t.Fatalf("unsupported selector accepted: %s", path)
		}
	}
}
