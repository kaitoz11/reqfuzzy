package flow_test

import (
	"context"
	"fmt"
	"github.com/imroc/req/v3"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
)

func TestCookieMutationUsesLiveJarAndIsRequestScoped(t *testing.T) {
	for _, tc := range []struct {
		action, value string
		want          []string
	}{
		{"set", `"changed"`, []string{"changed"}},
		{"remove", "", nil},
		{"append", `"-tail"`, []string{"fresh-tail"}},
		{"prepend", `"head-"`, []string{"head-fresh"}},
	} {
		t.Run(tc.action, func(t *testing.T) {
			seen := make(chan []string, 2)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/login" {
					http.SetCookie(w, &http.Cookie{Name: "sid", Value: "fresh", Path: "/"})
					http.SetCookie(w, &http.Cookie{Name: "keep", Value: "untouched", Path: "/"})
					fmt.Fprint(w, `{}`)
					return
				}
				var values []string
				for _, cookie := range r.Cookies() {
					if cookie.Name == "sid" {
						values = append(values, cookie.Value)
					}
				}
				seen <- values
				keep, err := r.Cookie("keep")
				if err != nil || keep.Value != "untouched" {
					http.Error(w, "lost unrelated cookie", 400)
					return
				}
				if r.URL.Path == "/target" {
					http.SetCookie(w, &http.Cookie{Name: "sid", Value: "rotated", Path: "/"})
				}
				fmt.Fprint(w, `{}`)
			}))
			defer server.Close()
			store := attacker.NewRequestStore()
			for _, name := range []string{"login", "target", "verify"} {
				registerRawRequest(t, store, name, "GET /"+name+" HTTP/1.1\r\nHost: capture.test\r\nCookie: sid=stale\r\n\r\n")
			}
			ok := 200
			definition := flow.Flow{Name: "cookies", Steps: []flow.Step{{ID: "login", Request: "login", ExpectStatus: &ok}, {ID: "target", Request: "target", ExpectStatus: &ok}, {ID: "verify", Request: "verify", ExpectStatus: &ok}}}
			runner := flow.Runner{Store: store, NewClient: func(string) (*attacker.HClient, error) {
				client := attacker.NewHClient()
				client.UseBaseURL(server.URL)
				return client, nil
			}}
			mutation, err := flow.BuildMutation(flow.MutationSpec{Action: tc.action, Location: "cookie", Path: "sid", Value: []byte(tc.value)})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := runner.Run(context.Background(), definition, &flow.StepMutation{StepID: "target", Apply: mutation}); err != nil {
				t.Fatal(err)
			}
			if got := <-seen; !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("target sid=%q want=%q", got, tc.want)
			}
			if got := <-seen; !reflect.DeepEqual(got, []string{"rotated"}) {
				t.Fatalf("server cookie rotation was not carried forward: %q", got)
			}
		})
	}
}

type cookieCountingTransport struct {
	next  http.RoundTripper
	calls *atomic.Int32
}

func (t cookieCountingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	t.calls.Add(1)
	return t.next.RoundTrip(request)
}

func TestCookieEditPreservesCommonCookiesAndCustomTransport(t *testing.T) {
	seen := make(chan []string, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	var calls atomic.Int32
	store := attacker.NewRequestStore()
	registerRawRequest(t, store, "target", "GET /target HTTP/1.1\r\n\r\n")
	registerRawRequest(t, store, "verify", "GET /verify HTTP/1.1\r\n\r\n")
	definition := flow.Flow{Name: "common-cookie", Steps: []flow.Step{{ID: "target", Request: "target"}, {ID: "verify", Request: "verify"}}}
	runner := flow.Runner{Store: store, NewClient: func(string) (*attacker.HClient, error) {
		client := attacker.NewHClient()
		client.UseBaseURL(server.URL)
		client.WithUpdatedClient(func(c *req.Client) {
			c.SetCommonCookies(&http.Cookie{Name: "sid", Value: "common"})
			c.GetClient().Transport = cookieCountingTransport{c.GetClient().Transport, &calls}
		})
		return client, nil
	}}
	mutation, err := flow.BuildMutation(flow.MutationSpec{Action: "set", Location: "cookie", Path: "sid", Value: []byte(`"changed"`)})
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Run(context.Background(), definition, &flow.StepMutation{StepID: "target", Apply: mutation})
	if err != nil {
		t.Fatal(err)
	}
	if got := <-seen; !reflect.DeepEqual(got, []string{"changed"}) {
		t.Fatalf("target sid=%q", got)
	}
	if got := <-seen; !reflect.DeepEqual(got, []string{"common"}) {
		t.Fatalf("common cookie changed across steps: %q", got)
	}
	if calls.Load() != 2 || result.Steps[0].SentRequest == nil {
		t.Fatalf("custom transport or observation bypassed: calls=%d", calls.Load())
	}
}

func TestCookieBindingOverridesJarValueBeforeHook(t *testing.T) {
	seen := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "jar-value", Path: "/"})
			fmt.Fprint(w, `{"sid":"response-value"}`)
			return
		}
		var values []string
		for _, cookie := range r.Cookies() {
			if cookie.Name == "sid" {
				values = append(values, cookie.Value)
			}
		}
		if len(values) != 1 || r.Header.Get("X-Signed-Cookie") != "sid=response-value" {
			http.Error(w, "cookie binding/signing mismatch", 400)
			return
		}
		seen <- values[0]
		w.WriteHeader(204)
	}))
	defer server.Close()
	store := attacker.NewRequestStore()
	registerRawRequest(t, store, "login", "GET /login HTTP/1.1\r\n\r\n")
	registerRawRequest(t, store, "target", "GET /target HTTP/1.1\r\nCookie: sid=stale\r\n\r\n")
	definition, err := flow.LoadYAML([]byte(`name: bind-cookie
steps:
  - {id: login, request: login, extract: [{name: sid, json: sid}]}
  - id: target
    request: target
    expect_status: 204
    bind: [{location: cookie, path: sid, variable: sid}]
    before_send: sign
`))
	if err != nil {
		t.Fatal(err)
	}
	runner := flow.Runner{Store: store, NewClient: func(string) (*attacker.HClient, error) {
		client := attacker.NewHClient()
		client.UseBaseURL(server.URL)
		return client, nil
	}, BeforeSend: map[string]flow.BeforeSend{"sign": func(request attacker.Request, _ flow.Variables) error {
		request.SetHeaderNonCanonical("X-Signed-Cookie", request.Headers.Get("Cookie"))
		return nil
	}}}
	if _, err := runner.Run(context.Background(), definition, nil); err != nil {
		t.Fatal(err)
	}
	if got := <-seen; got != "response-value" {
		t.Fatalf("sid=%q", got)
	}
}
