package campaign_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/campaign"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
)

func TestOpaqueRequestTransformRequiresExplicitOptIn(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		encoded, _ := io.ReadAll(r.Body)
		decoded, err := base64.StdEncoding.DecodeString(string(encoded))
		if err != nil {
			http.Error(w, "encoding", 400)
			return
		}
		var body struct {
			Amount int `json:"amount"`
		}
		if json.Unmarshal(decoded, &body) != nil {
			http.Error(w, "JSON", 400)
			return
		}
		json.NewEncoder(w).Encode(map[string]int{"received": body.Amount})
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "request.txt")
	if err := os.WriteFile(path, []byte("POST / HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\n\r\n{\"amount\":10}"), 0600); err != nil {
		t.Fatal(err)
	}
	store := attacker.NewRequestStore()
	store.RegisterRequestFilePath("send", path)
	status := 200
	main := flow.Flow{Name: "opaque", Steps: []flow.Step{{ID: "send", Request: "send", ExpectStatus: &status, BeforeSend: "encode"}}}
	runner := flow.Runner{Store: store, NewClient: func(string) (*attacker.HClient, error) {
		client := attacker.NewHClient()
		client.UseBaseURL(server.URL)
		return client, nil
	}, BeforeSend: map[string]flow.BeforeSend{"encode": func(request attacker.Request, _ flow.Variables) error {
		request.SetBodyString(base64.StdEncoding.EncodeToString(request.Body))
		return nil
	}}}
	spec := campaign.Spec{Version: 1, Name: "opaque", Target: campaign.Target{Step: "send", Location: "json", Path: "amount"}, ObserveStatuses: []int{200}, Cases: []campaign.Case{{ID: "negative", Action: "set", Value: campaign.Scalar("-10")}}, Checks: []campaign.Check{{ID: "same-result", Step: "send", Select: "json", Path: "received", Op: "eq", Baseline: true}}}
	result, err := campaign.Run(context.Background(), runner, main, nil, spec, campaign.Options{})
	if err != nil || result.Cases[0].Outcome != campaign.Inconclusive {
		t.Fatalf("implicit transformed request accepted: outcome=%s err=%v", result.Outcome, err)
	}
	spec.Target.AllowTransform = true
	result, err = campaign.Run(context.Background(), runner, main, nil, spec, campaign.Options{})
	if err != nil || result.Outcome != campaign.Fail || result.Cases[0].MutationProof != "transformed" {
		t.Fatalf("explicit transform outcome=%s err=%v", result.Outcome, err)
	}
}

func TestForcedJSONKeyMutationUsesSameLookupForProof(t *testing.T) {
	for _, erase := range []bool{false, true} {
		t.Run(fmt.Sprint(erase), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body map[string]int
				json.NewDecoder(r.Body).Decode(&body)
				json.NewEncoder(w).Encode(map[string]int{"received": body["0"]})
			}))
			defer server.Close()
			path := filepath.Join(t.TempDir(), "request.txt")
			os.WriteFile(path, []byte("POST / HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"0\":10}"), 0600)
			store := attacker.NewRequestStore()
			store.RegisterRequestFilePath("send", path)
			status := 200
			main := flow.Flow{Name: "forced-key", Steps: []flow.Step{{ID: "send", Request: "send", ExpectStatus: &status, BeforeSend: "prepare"}}}
			runner := flow.Runner{Store: store, NewClient: func(string) (*attacker.HClient, error) {
				c := attacker.NewHClient()
				c.UseBaseURL(server.URL)
				return c, nil
			}, BeforeSend: map[string]flow.BeforeSend{"prepare": func(request attacker.Request, _ flow.Variables) error {
				if erase {
					request.SetBodyString(`{"0":10}`)
				}
				return nil
			}}}
			spec := campaign.Spec{Version: 1, Name: "forced-key", Target: campaign.Target{Step: "send", Location: "json", Path: ":0"}, ObserveStatuses: []int{200}, Cases: []campaign.Case{{ID: "negative", Action: "set", Value: campaign.Scalar("-1")}}, Checks: []campaign.Check{{ID: "same", Step: "send", Select: "json", Path: "received", Op: "eq", Baseline: true}}}
			result, err := campaign.Run(context.Background(), runner, main, nil, spec, campaign.Options{})
			if err != nil {
				t.Fatal(err)
			}
			want := campaign.Fail
			if erase {
				want = campaign.Inconclusive
			}
			if result.Outcome != want {
				t.Fatalf("forced-key mutation/proof outcome=%s want=%s", result.Outcome, want)
			}
		})
	}
}

func TestStreamBodyCannotUseCachedMutationAsSentEvidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Amount int `json:"amount"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		json.NewEncoder(w).Encode(map[string]int{"received": body.Amount})
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "request.txt")
	os.WriteFile(path, []byte("POST / HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"amount\":10}"), 0600)
	store := attacker.NewRequestStore()
	store.RegisterRequestFilePath("send", path)
	status := 200
	main := flow.Flow{Name: "stream", Steps: []flow.Step{{ID: "send", Request: "send", ExpectStatus: &status, BeforeSend: "restore"}}}
	runner := flow.Runner{Store: store, NewClient: func(string) (*attacker.HClient, error) {
		c := attacker.NewHClient()
		c.UseBaseURL(server.URL)
		return c, nil
	}, BeforeSend: map[string]flow.BeforeSend{"restore": func(request attacker.Request, _ flow.Variables) error {
		request.SetBody(strings.NewReader(`{"amount":10}`))
		return nil
	}}}
	spec := campaign.Spec{Version: 1, Name: "stream", Target: campaign.Target{Step: "send", Location: "json", Path: "amount"}, ObserveStatuses: []int{200}, Cases: []campaign.Case{{ID: "negative", Action: "set", Value: campaign.Scalar("-1")}}, Checks: []campaign.Check{{ID: "same", Step: "send", Select: "json", Path: "received", Op: "eq", Baseline: true}}}
	result, err := campaign.Run(context.Background(), runner, main, nil, spec, campaign.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != campaign.Inconclusive {
		t.Fatalf("cached body made erased stream mutation assessable: %s", result.Outcome)
	}
	sent := result.Cases[0].Flow.Steps[0].SentRequest
	if sent == nil || string(sent.Body) != `{"amount":10}` {
		t.Fatalf("sent body is not the transport body: %#v", sent)
	}
}

func TestMiddlewareBodyProviderIsMarkedUnavailable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Amount int `json:"amount"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		json.NewEncoder(w).Encode(map[string]int{"received": body.Amount})
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "request.txt")
	if err := os.WriteFile(path, []byte("POST / HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"amount\":10}"), 0600); err != nil {
		t.Fatal(err)
	}
	store := attacker.NewRequestStore()
	store.RegisterRequestFilePath("send", path)
	status := 200
	main := flow.Flow{Name: "marshal", Steps: []flow.Step{{ID: "send", Request: "send", ExpectStatus: &status, BeforeSend: "restore"}}}
	runner := flow.Runner{Store: store, NewClient: func(string) (*attacker.HClient, error) {
		c := attacker.NewHClient()
		c.UseBaseURL(server.URL)
		return c, nil
	}, BeforeSend: map[string]flow.BeforeSend{"restore": func(request attacker.Request, _ flow.Variables) error {
		request.SetBody(map[string]int{"amount": 10})
		return nil
	}}}
	spec := campaign.Spec{Version: 1, Name: "marshal", Target: campaign.Target{Step: "send", Location: "json", Path: "amount"}, ObserveStatuses: []int{200}, Cases: []campaign.Case{{ID: "negative", Action: "set", Value: campaign.Scalar("-1")}}, Checks: []campaign.Check{{ID: "same", Step: "send", Select: "json", Path: "received", Op: "eq", Baseline: true}}}
	result, err := campaign.Run(context.Background(), runner, main, nil, spec, campaign.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != campaign.Inconclusive || len(result.Cases) != 1 {
		t.Fatalf("unknown body became assessable: %s", result.Outcome)
	}
	sent := result.Cases[0].Flow.Steps[0].SentRequest
	if sent == nil || sent.BodySource != "unavailable" || len(sent.Body) != 0 {
		t.Fatalf("middleware body used cached evidence: %#v", sent)
	}
}
