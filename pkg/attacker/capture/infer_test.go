package capture_test

import (
	"strings"
	"testing"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker/capture"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
)

func TestSuggestFlowLinksBearerTokenAndNumericTransactionID(t *testing.T) {
	parsed, err := capture.ParseHAR(sampleHAR())
	if err != nil {
		t.Fatal(err)
	}
	suggestion, err := capture.SuggestFlow(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if len(suggestion.Flow.Steps) != 3 || len(suggestion.Links) != 2 {
		t.Fatalf("steps=%d links=%#v", len(suggestion.Flow.Steps), suggestion.Links)
	}
	login := suggestion.Flow.Steps[0]
	transfer := suggestion.Flow.Steps[1]
	confirm := suggestion.Flow.Steps[2]
	if login.Request != "0001_get_api_login" || transfer.Request != "0002_post_api_transfer" || confirm.Request != "0003_post_api_confirm" {
		t.Fatalf("request names: %q %q %q", login.Request, transfer.Request, confirm.Request)
	}
	if len(login.Extract) != 1 || login.Extract[0].JSONPath != "token" || len(transfer.Bind) != 1 || transfer.Bind[0].Location != "header" || transfer.Bind[0].Path != "Authorization" || transfer.Bind[0].Prefix != "Bearer " {
		t.Fatalf("token link: login=%#v transfer=%#v", login.Extract, transfer.Bind)
	}
	if len(transfer.Extract) != 1 || transfer.Extract[0].JSONPath != "data.txnId" || len(confirm.Bind) != 1 || confirm.Bind[0].Location != "json" || confirm.Bind[0].Path != "txnId" {
		t.Fatalf("transaction link: transfer=%#v confirm=%#v", transfer.Extract, confirm.Bind)
	}
	if suggestion.Links[0].Confidence != "high" || suggestion.Links[1].Confidence != "medium" {
		t.Fatalf("link confidences = %#v", suggestion.Links)
	}
	yamlData, err := suggestion.YAML()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := flow.LoadYAML(yamlData)
	if err != nil {
		t.Fatalf("suggested flow YAML cannot be loaded: %v\n%s", err, yamlData)
	}
	if len(loaded.Steps) != 3 || loaded.Steps[2].Bind[0].Location != "json" {
		t.Fatalf("loaded flow = %#v", loaded)
	}
}

func TestSuggestFlowSkipsMissingAmbiguousAndShortSources(t *testing.T) {
	cases := []struct {
		name        string
		body        string
		bodyPresent bool
	}{
		{"missing body", `{"id":"secret123"}`, false},
		{"ambiguous JSON paths", `{"a":"secret123","b":"secret123"}`, true},
		{"short value", `{"id":"123"}`, true},
		{"same text in string and number", `{"string":"123456","number":123456}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			value := "secret123"
			if tc.name == "short value" {
				value = "123"
			} else if tc.name == "same text in string and number" {
				value = "123456"
			}
			archive := capture.Capture{Exchanges: []capture.Exchange{
				{Name: "source", URL: "http://example.test/source", RequestRaw: []byte("GET /source HTTP/1.1\r\nHost: example.test\r\n\r\n"), ResponseStatus: 200, ResponseBody: []byte(tc.body), ResponseBodyPresent: tc.bodyPresent},
				{Name: "target", URL: "http://example.test/target?id=" + value, RequestRaw: []byte("GET /target?id=" + value + " HTTP/1.1\r\nHost: example.test\r\n\r\n"), ResponseStatus: 200},
			}}
			suggestion, err := capture.SuggestFlow(archive)
			if err != nil {
				t.Fatal(err)
			}
			if len(suggestion.Links) != 0 {
				t.Fatalf("unexpected links = %#v", suggestion.Links)
			}
		})
	}
}

func TestSuggestFlowEscapesNestedJSONPaths(t *testing.T) {
	archive := capture.Capture{Exchanges: []capture.Exchange{
		{Name: "source", URL: "http://example.test/source", RequestRaw: []byte("GET /source HTTP/1.1\r\nHost: example.test\r\n\r\n"), ResponseBody: []byte(`{"data":{"items":[{"txn.id":"ABCDEF123"}]}}`), ResponseBodyPresent: true},
		{Name: "target", URL: "http://example.test/target", RequestRaw: []byte("POST /target HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\n\r\n{\"id\":\"ABCDEF123\"}")},
	}}
	suggestion, err := capture.SuggestFlow(archive)
	if err != nil {
		t.Fatal(err)
	}
	if len(suggestion.Links) != 1 || suggestion.Links[0].FromJSONPath != `data.items.0.txn\.id` || suggestion.Links[0].ToPath != "id" {
		t.Fatalf("nested link = %#v", suggestion.Links)
	}
	data, err := suggestion.YAML()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := flow.LoadYAML(data); err != nil {
		t.Fatalf("inferred YAML invalid: %v", err)
	}
	if strings.Contains(string(data), "ABCDEF123") {
		t.Fatal("suggested YAML copied a captured value")
	}
}
