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
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kaitoz11/reqfuzzy/internal/cli"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
	"gopkg.in/yaml.v3"
)

func call(args ...string) (int, string, string) {
	var out, err bytes.Buffer
	code := cli.Run(args, &out, &err)
	return code, out.String(), err.String()
}
func write(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
func har(t *testing.T, origin string) []byte {
	t.Helper()
	entries := []any{
		map[string]any{"request": map[string]any{"method": "POST", "url": origin + "/login", "headers": []any{}}, "response": map[string]any{"status": 200, "content": map[string]any{"text": `{"token":"captured-12345"}`}}},
		map[string]any{"request": map[string]any{"method": "POST", "url": origin + "/create", "headers": []any{map[string]string{"name": "Authorization", "value": "Bearer captured-12345"}}, "postData": map[string]any{"mimeType": "application/json", "text": `{"amount":10}`}}, "response": map[string]any{"status": 201, "content": map[string]any{"text": `{"id":9007199254740993}`}}},
		map[string]any{"request": map[string]any{"method": "POST", "url": origin + "/read", "headers": []any{}, "postData": map[string]any{"mimeType": "application/json", "text": `{"id":9007199254740993}`}}, "response": map[string]any{"status": 200, "content": map[string]any{"text": `{"amount":10}`}}},
	}
	data, err := json.Marshal(map[string]any{"log": map[string]any{"version": "1.2", "entries": entries}})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestImportScriptRunAndCompareCommands(t *testing.T) {
	var hits atomic.Int32
	var sessions atomic.Int32
	var mu sync.Mutex
	amounts := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/login":
			id := fmt.Sprint(sessions.Add(1))
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: id, Path: "/"})
			fmt.Fprintf(w, `{"token":"runtime-%s-12345"}`, id)
		case "/create":
			cookie, err := r.Cookie("sid")
			if err != nil || r.Header.Get("Authorization") != "Bearer runtime-"+cookie.Value+"-12345" {
				http.Error(w, "auth", 401)
				return
			}
			body, _ := io.ReadAll(r.Body)
			mac := hmac.New(sha256.New, []byte("key"))
			mac.Write(body)
			if r.Header.Get("X-Signature") != hex.EncodeToString(mac.Sum(nil)) || r.Header.Get("X-Observed-Host") != r.Host {
				http.Error(w, "signature or Host", 400)
				return
			}
			var payload struct {
				Amount int `json:"amount"`
			}
			if json.Unmarshal(body, &payload) != nil {
				http.Error(w, "body", 400)
				return
			}
			mu.Lock()
			amounts[cookie.Value] = payload.Amount
			mu.Unlock()
			w.WriteHeader(201)
			fmt.Fprint(w, `{"id":9007199254740993}`)
		case "/read":
			cookie, err := r.Cookie("sid")
			if err != nil {
				http.Error(w, "cookie", 401)
				return
			}
			var payload struct {
				ID json.Number `json:"id"`
			}
			if json.NewDecoder(r.Body).Decode(&payload) != nil || payload.ID.String() != "9007199254740993" {
				http.Error(w, "id", 400)
				return
			}
			mu.Lock()
			amount := amounts[cookie.Value]
			mu.Unlock()
			fmt.Fprintf(w, `{"amount":%d}`, amount)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	root := t.TempDir()
	input := filepath.Join(root, "capture.har")
	project := filepath.Join(root, "project")
	write(t, input, har(t, "http://capture.test"))
	code, out, stderr := call("import", "--out", project, "--json", input)
	if code != 0 || stderr != "" || hits.Load() != 0 {
		t.Fatalf("import code=%d out=%s err=%s hits=%d", code, out, stderr, hits.Load())
	}
	var imported map[string]any
	if err := json.Unmarshal([]byte(out), &imported); err != nil || imported["format_version"] != float64(1) {
		t.Fatalf("import JSON=%s err=%v", out, err)
	}
	code, _, _ = call("flow", "compare", "--project", project, "--base-url", server.URL, "--step", "missing", "--location", "json", "--path", "amount", "--value", "99")
	if code != 1 || hits.Load() != 0 {
		t.Fatalf("invalid mutation step code=%d hits=%d", code, hits.Load())
	}
	data, err := os.ReadFile(filepath.Join(project, "flow.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	definition, err := flow.LoadYAML(data)
	if err != nil {
		t.Fatal(err)
	}
	definition.Steps[0].Extract = nil
	definition.Steps[0].AfterResponse = "session"
	definition.Steps[0].Provides = []string{"token"}
	definition.Steps[1].Bind[0].Variable = "token"
	definition.Steps[1].BeforeSend = "sign"
	data, err = yaml.Marshal(definition)
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(project, "flow.yaml"), data)
	write(t, filepath.Join(project, "hooks", "session.js"), []byte(`function afterResponse(ctx){ctx.vars.set("token",JSON.parse(ctx.response.body).token);}`))
	write(t, filepath.Join(project, "hooks", "sign.js"), []byte(`function beforeSend(ctx){ctx.request.setHeader("X-Observed-Host",ctx.request.getHeader("Host"));ctx.request.setHeader("X-Signature",crypto.hmacSha256("key",ctx.request.body));}`))
	code, out, stderr = call("flow", "show", "--project", project, "--json")
	if code != 0 || !strings.Contains(out, "token") || hits.Load() != 0 {
		t.Fatalf("show code=%d out=%s err=%s", code, out, stderr)
	}
	code, out, stderr = call("flow", "run", "--project", project, "--base-url", server.URL, "--json")
	if code != 0 || stderr != "" || hits.Load() != 3 || strings.Contains(out, "runtime-") {
		t.Fatalf("run code=%d out=%s err=%s hits=%d", code, out, stderr, hits.Load())
	}
	code, out, stderr = call("flow", "compare", "--project", project, "--base-url", server.URL, "--step", definition.Steps[1].ID, "--location", "json", "--path", "amount", "--value", "99", "--json")
	if code != 0 || stderr != "" || hits.Load() != 9 {
		t.Fatalf("compare code=%d out=%s err=%s hits=%d", code, out, stderr, hits.Load())
	}
	var compared struct {
		Result struct {
			Baseline struct {
				Steps []struct {
					ResponseSHA string `json:"response_sha256"`
				}
			} `json:"baseline"`
			Mutated struct {
				Steps []struct {
					ResponseSHA string `json:"response_sha256"`
				}
			} `json:"mutated"`
		}
	}
	if err := json.Unmarshal([]byte(out), &compared); err != nil {
		t.Fatal(err)
	}
	if len(compared.Result.Baseline.Steps) != 3 || len(compared.Result.Mutated.Steps) != 3 || compared.Result.Baseline.Steps[2].ResponseSHA == compared.Result.Mutated.Steps[2].ResponseSHA {
		t.Fatalf("comparison summaries=%s", out)
	}
	write(t, filepath.Join(project, "hooks", "sign.js"), []byte(`function beforeSend(ctx){throw new Error("cannot sign");}`))
	code, out, stderr = call("flow", "run", "--project", project, "--base-url", server.URL, "--json")
	if code != 2 || !strings.Contains(out, `"failed_step_id":"`+definition.Steps[1].ID+`"`) || hits.Load() != 10 {
		t.Fatalf("throw code=%d out=%s err=%s hits=%d", code, out, stderr, hits.Load())
	}
	if err := os.Remove(filepath.Join(project, "hooks", "sign.js")); err != nil {
		t.Fatal(err)
	}
	code, _, _ = call("flow", "run", "--project", project, "--base-url", server.URL)
	if code != 1 || hits.Load() != 10 {
		t.Fatalf("missing script code=%d hits=%d", code, hits.Load())
	}
	code, _, _ = call("import", "--out", project, input)
	if code != 1 {
		t.Fatal("import overwrote edited project")
	}
}

func TestMultiOriginImportRequiresSelection(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "capture.har")
	data := bytes.Replace(har(t, "https://one.test"), []byte("https://one.test/read"), []byte("https://two.test/read"), 1)
	write(t, input, data)
	code, _, _ := call("import", "--out", filepath.Join(root, "bad"), input)
	if code != 1 {
		t.Fatal("multi-origin capture accepted without selection")
	}
	code, _, stderr := call("import", "--origin", "https://one.test", "--out", filepath.Join(root, "selected"), input)
	if code != 0 {
		t.Fatalf("selected import failed: %s", stderr)
	}
}

func TestProjectTraversalIsRejectedBeforeNetwork(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "project.yaml"), []byte("version: 1\norigin: http://example.test\nrequests:\n  one: ../outside.txt\n"))
	write(t, filepath.Join(root, "flow.yaml"), []byte("name: bad\nsteps: [{id: one, request: one}]\n"))
	code, _, _ := call("flow", "run", "--project", root, "--base-url", "http://127.0.0.1:1")
	if code != 1 {
		t.Fatalf("traversal code=%d, want config error", code)
	}
}

func TestCommandDeadlineCoversScriptPreflight(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer server.Close()
	root := t.TempDir()
	input := filepath.Join(root, "capture.har")
	project := filepath.Join(root, "project")
	write(t, input, har(t, "http://capture.test"))
	if code, _, err := call("import", "--out", project, input); code != 0 {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(project, "flow.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	definition, err := flow.LoadYAML(data)
	if err != nil {
		t.Fatal(err)
	}
	definition.Steps[0].BeforeSend = "hang"
	data, _ = yaml.Marshal(definition)
	write(t, filepath.Join(project, "flow.yaml"), data)
	write(t, filepath.Join(project, "hooks", "hang.js"), []byte(`for(;;){} function beforeSend(ctx){}`))
	started := time.Now()
	code, out, stderr := call("flow", "run", "--project", project, "--base-url", server.URL, "--timeout", "20ms", "--script-timeout", "1s", "--json")
	if code != 2 || hits.Load() != 0 || time.Since(started) > 500*time.Millisecond {
		t.Fatalf("code=%d out=%s err=%s hits=%d elapsed=%s", code, out, stderr, hits.Load(), time.Since(started))
	}
}
