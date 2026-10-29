package flow_test

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
)

func TestFormBindingRejectsInvalidCapturedEncodingBeforeClients(t *testing.T) {
	for _, raw := range []string{
		"POST / HTTP/1.1\r\nContent-Type: text/plain\r\n\r\nid=base",
		"POST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded; charset=iso-8859-1\r\n\r\nid=base",
		"POST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nid=base",
		"POST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nid=base&bad=%FF",
		"POST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Encoding: gzip\r\n\r\nid=base",
	} {
		store := attacker.NewRequestStore()
		registerRawRequest(t, store, "source", "GET /source HTTP/1.1\r\n\r\n")
		registerRawRequest(t, store, "target", raw)
		definition := flow.Flow{Name: "preflight-form", Steps: []flow.Step{
			{ID: "source", Request: "source", Extract: []flow.Extraction{{Name: "id", JSONPath: "id"}}},
			{ID: "target", Request: "target", Bind: []flow.Binding{{Location: "form", Path: "id", Variable: "id"}}},
		}}
		var clients atomic.Int32
		runner := flow.Runner{Store: store, NewClient: func(string) (*attacker.HClient, error) {
			clients.Add(1)
			return nil, fmt.Errorf("must fail before clients")
		}}
		if _, err := runner.Run(context.Background(), definition, nil); err == nil || clients.Load() != 0 {
			t.Fatalf("form preflight err=%v clients=%d", err, clients.Load())
		}
	}
}

func TestPathRemovalRejectsNetworkReferenceAndNoOp(t *testing.T) {
	for _, path := range []string{"/one//rest", "/"} {
		request, err := attacker.NewHClient().ParseRawRequest([]byte("GET " + path + " HTTP/1.1\r\n\r\n"))
		if err != nil {
			t.Fatal(err)
		}
		mutation, err := flow.BuildMutation(flow.MutationSpec{Action: "remove", Location: "path", Path: "0"})
		if err != nil {
			t.Fatal(err)
		}
		if err := mutation(request, nil); err == nil || request.RawURL != path {
			t.Fatalf("invalid removal changed request: err=%v path=%q", err, request.RawURL)
		}
	}
}
