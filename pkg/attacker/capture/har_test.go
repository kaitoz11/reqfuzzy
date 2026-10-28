package capture_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker/capture"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/rawreq"
)

func sampleHAR() []byte {
	loginResponse := base64.StdEncoding.EncodeToString([]byte(`{"token":"token-12345"}`))
	transferBody := "{\n  \"amount\": 10\n}"
	return []byte(fmt.Sprintf(`{"log":{"version":"1.2","entries":[
{"request":{"method":"GET","url":"http://example.test/api/login","httpVersion":"HTTP/2","headers":[{"name":"X-Trace","value":"one"}]},"response":{"status":200,"content":{"text":%q,"encoding":"base64","mimeType":"application/json"}}},
{"request":{"method":"POST","url":"http://example.test/api/transfer?foo=1&foo=2","httpVersion":"HTTP/1.1","headers":[{"name":"Authorization","value":"Bearer token-12345"},{"name":"Content-Length","value":"99"}],"postData":{"mimeType":"application/json","text":%q}},"response":{"status":201,"content":{"text":"{\"data\":{\"txnId\":9007199254740993}}","mimeType":"application/json"}}},
{"request":{"method":"POST","url":"http://example.test/api/confirm","headers":[{"name":"Content-Type","value":"application/json"}],"postData":{"mimeType":"application/json","text":"{\"txnId\":9007199254740993}"}},"response":{"status":200,"content":{"text":"{\"ok\":true}","mimeType":"application/json"}}}
]}}`, loginResponse, transferBody))
}

func TestParseHARPreservesReplayableRequestAndResponseData(t *testing.T) {
	got, err := capture.ParseHAR(sampleHAR())
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Exchanges) != 3 {
		t.Fatalf("exchanges = %d, want 3", len(got.Exchanges))
	}
	if got.Exchanges[0].Name != "0001_get_api_login" || got.Exchanges[1].Name != "0002_post_api_transfer" || got.Exchanges[2].Name != "0003_post_api_confirm" {
		t.Fatalf("names = %q, %q, %q", got.Exchanges[0].Name, got.Exchanges[1].Name, got.Exchanges[2].Name)
	}
	if string(got.Exchanges[0].ResponseBody) != `{"token":"token-12345"}` || !got.Exchanges[0].ResponseBodyPresent {
		t.Fatalf("decoded login response = %q", got.Exchanges[0].ResponseBody)
	}
	if !bytes.HasPrefix(got.Exchanges[1].RequestRaw, []byte("POST /api/transfer?foo=1&foo=2 HTTP/1.1\r\n")) {
		t.Fatalf("transfer request line = %q", bytes.SplitN(got.Exchanges[1].RequestRaw, []byte("\r\n"), 2)[0])
	}
	if bytes.Contains(got.Exchanges[1].RequestRaw, []byte("Content-Length: 99")) {
		t.Fatalf("stale content length retained: %q", got.Exchanges[1].RequestRaw)
	}
	for _, exchange := range got.Exchanges {
		if _, err := rawreq.ParseRawRequest(exchange.RequestRaw); err != nil {
			t.Fatalf("request %s cannot be replayed: %v", exchange.Name, err)
		}
	}
	parsedTransfer, err := rawreq.ParseRawRequest(got.Exchanges[1].RequestRaw)
	if err != nil {
		t.Fatal(err)
	}
	if string(parsedTransfer.Body) != "{\n  \"amount\": 10\n}" {
		t.Fatalf("multiline body = %q", parsedTransfer.Body)
	}
	if !strings.Contains(string(got.Exchanges[1].RequestRaw), "Host: example.test\r\n") {
		t.Fatalf("Host header missing: %q", got.Exchanges[1].RequestRaw)
	}
}

func TestParseHARRejectsUnreplayableEntries(t *testing.T) {
	encodedLogin := base64.StdEncoding.EncodeToString([]byte(`{"token":"token-12345"}`))
	cases := []struct {
		name string
		data []byte
		want string
	}{
		{"wrong version", []byte(strings.Replace(string(sampleHAR()), `"version":"1.2"`, `"version":"1.1"`, 1)), "unsupported HAR version"},
		{"relative URL", []byte(strings.Replace(string(sampleHAR()), `http://example.test/api/login`, `/api/login`, 1)), "HAR entry 1"},
		{"newline in header", []byte(strings.Replace(string(sampleHAR()), `"value":"one"`, `"value":"one\nother"`, 1)), "invalid header"},
		{"invalid header name", []byte(strings.Replace(string(sampleHAR()), `"name":"X-Trace"`, `"name":"Bad/Name"`, 1)), "invalid header"},
		{"control byte in header value", []byte(strings.Replace(string(sampleHAR()), `"value":"one"`, `"value":"one\u0000two"`, 1)), "invalid header"},
		{"invalid method token", []byte(strings.Replace(string(sampleHAR()), `"method":"GET"`, `"method":"GE/T"`, 1)), "invalid request method"},
		{"URL userinfo", []byte(strings.Replace(string(sampleHAR()), `http://example.test/api/login`, `http://user:pass@example.test/api/login`, 1)), "invalid absolute HTTP URL"},
		{"postData MIME header injection", []byte(`{"log":{"version":"1.2","entries":[{"request":{"method":"POST","url":"http://example.test/upload","postData":{"mimeType":"application/json\r\nX-Evil: yes","text":"{}"}},"response":{"status":200}}]}}`), "invalid postData MIME type"},
		{"multipart params without text", []byte(`{"log":{"version":"1.2","entries":[{"request":{"method":"POST","url":"http://example.test/upload","postData":{"mimeType":"multipart/form-data","params":[{"name":"file","value":"x"}]}},"response":{"status":200}}]}}`), "cannot be replayed"},
		{"bad base64", []byte(strings.Replace(string(sampleHAR()), encodedLogin, "not-base64!", 1)), "decode base64 response"},
		{"unknown encoding", []byte(strings.Replace(string(sampleHAR()), `"encoding":"base64"`, `"encoding":"rot13"`, 1)), "unsupported response encoding"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := capture.ParseHAR(tc.data)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestParseHARGeneratedNameIsSafeForValidMethodToken(t *testing.T) {
	archive := []byte(strings.Replace(string(sampleHAR()), `"method":"GET"`, `"method":"M!X"`, 1))
	parsed, err := capture.ParseHAR(archive)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(parsed.Exchanges[0].Name, `!/\`) {
		t.Fatalf("generated name %q is not file-safe", parsed.Exchanges[0].Name)
	}
	if _, err := parsed.WriteRequests(t.TempDir()); err != nil {
		t.Fatalf("generated name cannot be written: %v", err)
	}
}

func TestParseHARHandlesMissingBodyAndFormParams(t *testing.T) {
	archive := []byte(`{"log":{"version":"1.2","entries":[
{"request":{"method":"POST","url":"http://example.test/form","postData":{"mimeType":"application/x-www-form-urlencoded","params":[{"name":"a","value":"1"},{"name":"b","value":"two words"}]}},"response":{"status":204,"content":{}}}
]}}`)
	archive = append([]byte{0xef, 0xbb, 0xbf}, archive...)
	got, err := capture.ParseHAR(archive)
	if err != nil {
		t.Fatal(err)
	}
	if got.Exchanges[0].ResponseStatus != 204 || got.Exchanges[0].ResponseBodyPresent {
		t.Fatalf("missing response body misrepresented: %#v", got.Exchanges[0])
	}
	parsed, err := rawreq.ParseRawRequest(got.Exchanges[0].RequestRaw)
	if err != nil {
		t.Fatal(err)
	}
	if string(parsed.Body) != "a=1&b=two+words" {
		t.Fatalf("form body = %q", parsed.Body)
	}
}
