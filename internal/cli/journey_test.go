package cli_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kaitoz11/reqfuzzy/internal/reference"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/campaign"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
	"gopkg.in/yaml.v3"
)

type captureTransport struct {
	base    http.RoundTripper
	entries []any
}

func (c *captureTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	body := []byte(nil)
	if request.Body != nil {
		body, _ = io.ReadAll(request.Body)
		request.Body = io.NopCloser(bytes.NewReader(body))
	}
	response, err := c.base.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	received, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		return nil, err
	}
	response.Body = io.NopCloser(bytes.NewReader(received))
	headers := []map[string]string{}
	keys := []string{}
	for key := range request.Header {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		for _, value := range request.Header[key] {
			headers = append(headers, map[string]string{"name": key, "value": value})
		}
	}
	captured := map[string]any{"method": request.Method, "url": request.URL.String(), "headers": headers}
	if len(body) > 0 {
		captured["postData"] = map[string]string{"mimeType": "application/json", "text": string(body)}
	}
	c.entries = append(c.entries, map[string]any{"request": captured, "response": map[string]any{"status": response.StatusCode, "content": map[string]string{"text": string(received), "mimeType": "application/json"}}})
	return response, nil
}

func capturedReferenceProject(t *testing.T, vulnerable bool) (string, string, *atomic.Int32) {
	t.Helper()
	handler := reference.NewHandler(reference.Options{VulnerableAmounts: vulnerable})
	hits := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); handler.ServeHTTP(w, r) }))
	t.Cleanup(server.Close)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	t.Cleanup(transport.CloseIdleConnections)
	capture := &captureTransport{base: transport}
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Transport: capture, Jar: jar}
	send := func(method, path, body, token, signature string) []byte {
		req, _ := http.NewRequest(method, server.URL+path, strings.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if signature != "" {
			req.Header.Set("X-Signature", signature)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		if resp.StatusCode >= 400 {
			t.Fatalf("reference capture %s status=%d body=%s", path, resp.StatusCode, data)
		}
		return data
	}
	var session struct {
		Token string `json:"access_token"`
		Key   string `json:"signing_key"`
	}
	if err := json.Unmarshal(send("POST", "/session", "{}", "", ""), &session); err != nil {
		t.Fatal(err)
	}
	var nonce struct {
		Value string `json:"nonce"`
	}
	json.Unmarshal(send("GET", "/nonce", "", session.Token, ""), &nonce)
	body := fmt.Sprintf(`{"amount":10,"nonce":%q}`, nonce.Value)
	mac := hmac.New(sha256.New, []byte(session.Key))
	mac.Write([]byte(body))
	send("POST", "/transfer", body, session.Token, hex.EncodeToString(mac.Sum(nil)))
	send("GET", "/balance", "", session.Token, "")
	data, _ := json.Marshal(map[string]any{"log": map[string]any{"version": "1.2", "entries": capture.entries}})
	root := t.TempDir()
	input := filepath.Join(root, "actual.har")
	project := filepath.Join(root, "project")
	write(t, input, data)
	if code, out, err := call("import", "--out", project, "--json", input); code != 0 {
		t.Fatalf("import code=%d out=%s err=%s", code, out, err)
	}
	raw, _ := os.ReadFile(filepath.Join(project, "flow.yaml"))
	imported, err := flow.LoadYAML(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(imported.Steps) != 4 {
		t.Fatalf("capture steps=%d", len(imported.Steps))
	}
	main := flow.Flow{Name: "reference-transfer", Steps: []flow.Step{
		{ID: "session", Request: imported.Steps[0].Request, Extract: []flow.Extraction{{Name: "token", JSONPath: "access_token"}, {Name: "signing_key", JSONPath: "signing_key"}, {Name: "initial_balance", JSONPath: "balance"}}},
		{ID: "nonce", Request: imported.Steps[1].Request, Bind: []flow.Binding{{Location: "header", Path: "Authorization", Variable: "token", Prefix: "Bearer "}}, Extract: []flow.Extraction{{Name: "nonce", JSONPath: "nonce"}}},
		{ID: "transfer", Request: imported.Steps[2].Request, Bind: []flow.Binding{{Location: "header", Path: "Authorization", Variable: "token", Prefix: "Bearer "}, {Location: "json", Path: "nonce", Variable: "nonce"}}, BeforeSend: "sign"},
	}}
	ok := 200
	created := 201
	main.Steps[0].ExpectStatus = &ok
	main.Steps[1].ExpectStatus = &ok
	main.Steps[2].ExpectStatus = &created
	verification := flow.Flow{Name: "verify", Steps: []flow.Step{{ID: "balance", Request: imported.Steps[3].Request, Bind: []flow.Binding{{Location: "header", Path: "Authorization", Variable: "token", Prefix: "Bearer "}}, ExpectStatus: &ok}}}
	data, _ = yaml.Marshal(main)
	write(t, filepath.Join(project, "flow.yaml"), data)
	data, _ = yaml.Marshal(verification)
	write(t, filepath.Join(project, "verify.yaml"), data)
	write(t, filepath.Join(project, "hooks", "sign.js"), []byte(`function beforeSend(ctx){ctx.request.setHeader("X-Signature",crypto.hmacSha256(ctx.vars.get("signing_key"),ctx.request.body));}`))
	write(t, filepath.Join(project, "tests.yaml"), []byte(`version: 1
name: amount-invariant
target: {step: transfer, location: json, path: amount}
observe_statuses: [201, 400, 422, 500]
verify: verify.yaml
cases:
  - {id: negative, action: set, value: -10}
  - {id: missing, action: remove}
checks:
  - {id: no-balance-increase, phase: verify, step: balance, select: json, path: balance, op: lte, variable: initial_balance}
`))
	return project, server.URL, hits
}

func TestActualCapturedJourneyCampaignEvidenceAndReplay(t *testing.T) {
	for _, vulnerable := range []bool{false, true} {
		t.Run(fmt.Sprint(vulnerable), func(t *testing.T) {
			project, base, hits := capturedReferenceProject(t, vulnerable)
			outDir := filepath.Join(t.TempDir(), "run")
			code, out, stderr := call("flow", "test", "--project", project, "--base-url", base, "--out", outDir, "--json")
			wantCode := 0
			want := campaign.Pass
			if vulnerable {
				wantCode = 3
				want = campaign.Fail
			}
			if code != wantCode || stderr != "" {
				t.Fatalf("test code=%d out=%s err=%s", code, out, stderr)
			}
			var result struct {
				Result struct {
					Outcome campaign.Outcome `json:"outcome"`
					Cases   []struct {
						ID      string           `json:"id"`
						Outcome campaign.Outcome `json:"outcome"`
					} `json:"cases"`
				} `json:"result"`
			}
			if err := json.Unmarshal([]byte(out), &result); err != nil || result.Result.Outcome != want || len(result.Result.Cases) != 2 {
				t.Fatalf("test summary=%s err=%v", out, err)
			}
			for _, name := range []string{"plan.json", "baseline.json", "negative.json", "missing.json", "result.json"} {
				data, err := os.ReadFile(filepath.Join(outDir, name))
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(data), "reference-token-") || strings.Contains(string(data), "reference-signing-") {
					t.Fatalf("artifact %s leaked session credentials", name)
				}
				info, _ := os.Stat(filepath.Join(outDir, name))
				if info.Mode().Perm() != 0600 {
					t.Fatal("artifact not private")
				}
			}
			replayDir := filepath.Join(t.TempDir(), "replay")
			code, out, stderr = call("flow", "replay", "--project", project, "--base-url", base, "--run", outDir, "--case", "negative", "--out", replayDir, "--json")
			if code != wantCode {
				t.Fatalf("replay code=%d out=%s err=%s", code, out, stderr)
			}
			before := hits.Load()
			write(t, filepath.Join(project, "hooks", "sign.js"), []byte(`function beforeSend(ctx){throw new Error("edited");}`))
			code, out, stderr = call("flow", "replay", "--project", project, "--base-url", base, "--run", outDir, "--case", "negative", "--out", filepath.Join(t.TempDir(), "drift"), "--json")
			if code != 1 || hits.Load() != before {
				t.Fatalf("drift replay sent traffic: code=%d hits=%d/%d out=%s err=%s", code, hits.Load(), before, out, stderr)
			}
		})
	}
}

func TestJourneyRequestBudgetRejectsBeforeTraffic(t *testing.T) {
	project, base, hits := capturedReferenceProject(t, false)
	before := hits.Load()
	directory := filepath.Join(t.TempDir(), "run")
	code, out, stderr := call("flow", "test", "--project", project, "--base-url", base, "--out", directory, "--max-requests", "1", "--json")
	if code != 1 || hits.Load() != before || !strings.Contains(out+stderr, "max-requests") {
		t.Fatalf("budget code=%d hits=%d/%d out=%s err=%s", code, hits.Load(), before, out, stderr)
	}
	if _, err := os.Stat(directory); !os.IsNotExist(err) {
		t.Fatal("rejected plan created evidence output")
	}
}
