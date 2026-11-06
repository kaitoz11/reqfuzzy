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
	"sync/atomic"
	"testing"

	"github.com/kaitoz11/reqfuzzy/internal/uploadref"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
	"github.com/tidwall/gjson"
	"gopkg.in/yaml.v3"
)

func TestActualMultipartCaptureBinarySigningCampaignAndReplay(t *testing.T) {
	for _, vulnerable := range []bool{false, true} {
		t.Run(fmt.Sprint(vulnerable), func(t *testing.T) {
			api := uploadref.New(vulnerable)
			var hits, binaryUploads atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				if r.URL.Path == "/upload" {
					body, _ := io.ReadAll(r.Body)
					if bytes.Contains(body, []byte{0, 255, 1, 'f', 'i', 'l', 'e'}) {
						binaryUploads.Add(1)
					}
					r.Body = io.NopCloser(bytes.NewReader(body))
				}
				api.ServeHTTP(w, r)
			}))
			defer server.Close()
			transport := http.DefaultTransport.(*http.Transport).Clone()
			defer transport.CloseIdleConnections()
			captured := &captureTransport{base: transport}
			client := &http.Client{Transport: captured}
			send := func(method, path, body, token, signature, contentType string) []byte {
				r, _ := http.NewRequest(method, server.URL+path, strings.NewReader(body))
				if token != "" {
					r.Header.Set("Authorization", "Bearer "+token)
				}
				if signature != "" {
					r.Header.Set("X-Signature", signature)
				}
				if contentType != "" {
					r.Header.Set("Content-Type", contentType)
				}
				resp, err := client.Do(r)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				data, _ := io.ReadAll(resp.Body)
				if resp.StatusCode >= 400 {
					t.Fatalf("capture %s: %d", path, resp.StatusCode)
				}
				return data
			}
			session := send("POST", "/session", "{}", "", "", "application/json")
			token := gjson.GetBytes(session, "token").String()
			key := gjson.GetBytes(session, "signing_key").String()
			nonce := gjson.GetBytes(session, "nonce").String()
			raw, err := os.ReadFile(filepath.Join("..", "..", "examples", "multipart", "requests", "upload.txt"))
			if err != nil {
				t.Fatal(err)
			}
			_, body, _ := strings.Cut(string(raw), "\r\n\r\n")
			body = strings.ReplaceAll(body, "captured-nonce", nonce)
			mac := hmac.New(sha256.New, []byte(key))
			mac.Write([]byte(body))
			send("POST", "/upload", body, token, hex.EncodeToString(mac.Sum(nil)), "multipart/form-data; boundary=CapturedUpload")
			send("GET", "/state", "", token, "", "")
			root := t.TempDir()
			input := filepath.Join(root, "actual.har")
			project := filepath.Join(root, "project")
			data, _ := json.Marshal(map[string]any{"log": map[string]any{"version": "1.2", "entries": captured.entries}})
			write(t, input, data)
			if code, out, stderr := call("import", "--out", project, "--json", input); code != 0 {
				t.Fatalf("import code=%d out=%s err=%s", code, out, stderr)
			}
			data, _ = os.ReadFile(filepath.Join(project, "flow.yaml"))
			inferred, err := flow.LoadYAML(data)
			if err != nil {
				t.Fatal(err)
			}
			found := map[string]bool{}
			for _, binding := range inferred.Steps[1].Bind {
				found[binding.Location] = true
			}
			if !found["multipart"] || !found["multipart-filename"] || !found["multipart-content-type"] {
				t.Fatalf("inferred bindings=%+v", inferred.Steps[1].Bind)
			}
			// Retain imported raw requests, then author the binary value source and hooks.
			example := filepath.Join("..", "..", "examples", "multipart")
			for _, name := range []string{"flow.yaml", "verify.yaml", "tests.yaml"} {
				data, _ = os.ReadFile(filepath.Join(example, name))
				write(t, filepath.Join(project, name), data)
			}
			if err := os.CopyFS(filepath.Join(project, "hooks"), os.DirFS(filepath.Join(example, "hooks"))); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"flow.yaml", "verify.yaml"} {
				data, _ = os.ReadFile(filepath.Join(project, name))
				var authored flow.Flow
				if err := yaml.Unmarshal(data, &authored); err != nil {
					t.Fatal(err)
				}
				for i := range authored.Steps {
					index := 0
					switch authored.Steps[i].Request {
					case "upload":
						index = 1
					case "state":
						index = 2
					}
					authored.Steps[i].Request = inferred.Steps[index].Request
				}
				data, _ = yaml.Marshal(authored)
				write(t, filepath.Join(project, name), data)
			}
			before := hits.Load()
			if code, out, stderr := call("flow", "test", "--project", project, "--base-url", server.URL, "--out", filepath.Join(root, "budget"), "--max-requests", "1", "--json"); code != 1 || hits.Load() != before {
				t.Fatalf("budget code=%d out=%s err=%s", code, out, stderr)
			}
			run := filepath.Join(root, "run")
			wantCode := 0
			if vulnerable {
				wantCode = 3
			}
			code, out, stderr := call("flow", "test", "--project", project, "--base-url", server.URL, "--out", run, "--json")
			if code != wantCode || gjson.Get(out, "result.cases.#").Int() != 2 || gjson.Get(out, "result.cases.0.mutation_proof").String() != "verified" {
				t.Fatalf("test code=%d out=%s err=%s", code, out, stderr)
			}
			if binaryUploads.Load() != 3 {
				t.Fatalf("expected baseline + 2 signed binary uploads, got %d", binaryUploads.Load())
			}
			code, out, stderr = call("flow", "replay", "--project", project, "--base-url", server.URL, "--run", run, "--case", "traversal-000001", "--out", filepath.Join(root, "replay"), "--json")
			if code != wantCode || binaryUploads.Load() != 5 {
				t.Fatalf("replay code=%d binary=%d out=%s err=%s", code, binaryUploads.Load(), out, stderr)
			}
			evidence, _ := os.ReadFile(filepath.Join(run, "traversal-000001.json"))
			if strings.Contains(string(evidence), "upload-key-") || !gjson.GetBytes(evidence, "flow.steps.1.sent.body.omitted").Bool() || !strings.Contains(string(evidence), "sha256") {
				t.Fatal("normal evidence must hash opaque multipart bodies")
			}
			before = hits.Load()
			write(t, filepath.Join(project, "hooks", "sign.js"), []byte(`function beforeSend(ctx){}`))
			if code, out, stderr := call("flow", "replay", "--project", project, "--base-url", server.URL, "--run", run, "--case", "traversal-000001", "--out", filepath.Join(root, "drift"), "--json"); code != 1 || hits.Load() != before {
				t.Fatalf("drift code=%d out=%s err=%s", code, out, stderr)
			}
		})
	}
}
