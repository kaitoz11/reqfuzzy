package cli_test

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
	"github.com/tidwall/gjson"
	"gopkg.in/yaml.v3"
)

// This acceptance test catches stale captured IDs/tokens, hooks erasing a
// mutation, and verdicts that ignore the persisted effect of that mutation.
// It is opt-in because it creates accounts/orders in a separate local app.
func TestJuiceShopCapturedCheckoutAndReplay(t *testing.T) {
	base := os.Getenv("REQFUZZY_JUICE_SHOP_URL")
	if base == "" {
		t.Skip("set REQFUZZY_JUICE_SHOP_URL to a local Juice Shop v20.3.0 instance")
	}
	parsed, err := url.Parse(base)
	if err != nil || parsed.Scheme != "http" || parsed.Hostname() != "127.0.0.1" || parsed.Port() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" {
		t.Fatal("acceptance target must be http://127.0.0.1:PORT")
	}
	template := filepath.Join("..", "..", "examples", "juice-shop")
	if _, err := os.Stat(filepath.Join(template, "flow.yaml")); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if persistent := os.Getenv("REQFUZZY_ACCEPTANCE_OUT"); persistent != "" {
		root, err = filepath.Abs(persistent)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(root, 0700); err != nil {
			t.Fatal("acceptance output must be a new directory:", err)
		}
	}
	t.Log("private acceptance artifacts:", root)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	t.Cleanup(transport.CloseIdleConnections)
	capture := &captureTransport{base: transport}
	client := &http.Client{Transport: capture, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	send := func(method, path string, body any, token string, want int) []byte {
		t.Helper()
		var encoded []byte
		if body != nil {
			encoded, err = json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
		}
		request, err := http.NewRequest(method, base+path, strings.NewReader(string(encoded)))
		if err != nil {
			t.Fatal(err)
		}
		if body != nil {
			request.Header.Set("Content-Type", "application/json")
		}
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("local application request failed:", err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(response.Body)
		if err != nil || response.StatusCode != want {
			t.Fatalf("%s %s: status=%d want=%d read error=%v", method, path, response.StatusCode, want, err)
		}
		return data
	}
	version := send("GET", "/rest/admin/application-version", nil, "", 200)
	if gjson.GetBytes(version, "version").String() != "20.3.0" {
		t.Fatal("acceptance requires Juice Shop v20.3.0")
	}
	capture.entries = nil // Keep only the six business requests in the HAR.
	var suffix [16]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatal(err)
	}
	email := "reqfuzzy-" + hex.EncodeToString(suffix[:]) + "@example.invalid"
	const password = "Local-Acceptance-Only-123!"
	send("POST", "/api/Users", map[string]any{"email": email, "password": password, "passwordRepeat": password}, "", 201)
	login := send("POST", "/rest/user/login", map[string]any{"email": email, "password": password}, "", 200)
	token := gjson.GetBytes(login, "authentication.token").String()
	basket := gjson.GetBytes(login, "authentication.bid").Int()
	if token == "" || basket <= 0 {
		t.Fatal("login did not create a session and basket")
	}
	added := send("POST", "/api/BasketItems", map[string]any{"BasketId": basket, "ProductId": 1, "quantity": 1}, token, 200)
	item := gjson.GetBytes(added, "data.id").Int()
	if item <= 0 {
		t.Fatal("add item did not return an ID")
	}
	send("PUT", fmt.Sprintf("/api/BasketItems/%d", item), map[string]any{"quantity": 2}, token, 200)
	order := send("POST", fmt.Sprintf("/rest/basket/%d/checkout", basket), map[string]any{}, token, 200)
	history := send("GET", "/rest/order-history", nil, token, 200)
	if gjson.GetBytes(history, "data.#").Int() != 1 || gjson.GetBytes(history, "data.0.orderId").String() != gjson.GetBytes(order, "orderConfirmation").String() || math.Abs(gjson.GetBytes(history, "data.0.totalPrice").Float()-3.98) > 1e-9 {
		t.Fatal("independent capture did not persist the expected positive order")
	}
	har, err := json.Marshal(map[string]any{"log": map[string]any{"version": "1.2", "entries": capture.entries}})
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(root, "actual.har")
	write(t, input, har)
	project := filepath.Join(root, "project")
	if code, out, stderr := call("import", "--out", project, "--json", input); code != 0 {
		t.Fatalf("import code=%d out=%s err=%s", code, out, stderr)
	}
	data, err := os.ReadFile(filepath.Join(project, "flow.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(project, "imported-flow.yaml"), data)
	imported, err := flow.LoadYAML(data)
	if err != nil || len(imported.Steps) != 6 {
		t.Fatalf("imported flow steps=%d err=%v", len(imported.Steps), err)
	}
	authLinks := 0
	for _, step := range imported.Steps {
		for _, binding := range step.Bind {
			if binding.Location == "header" && binding.Path == "Authorization" && binding.Prefix == "Bearer " {
				authLinks++
			}
		}
	}
	if authLinks != 4 {
		t.Fatalf("capture inferred %d authorization links, want 4", authLinks)
	}
	var manifest struct {
		Requests map[string]string `yaml:"requests"`
	}
	data, err = os.ReadFile(filepath.Join(project, "project.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	// Keep captured requests; replace the draft with reviewed dependencies and
	// explicit hooks for IDs in URL paths (outside current inference support).
	names := []string{"signup", "login", "add", "update", "checkout", "history"}
	for i, step := range imported.Steps {
		old := filepath.Join(project, manifest.Requests[step.Request])
		data, err := os.ReadFile(old)
		if err != nil {
			t.Fatal(err)
		}
		write(t, filepath.Join(project, "requests", names[i]+".txt"), data)
		if err := os.Remove(old); err != nil {
			t.Fatal(err)
		}
	}
	if err := filepath.WalkDir(template, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return walkErr
		}
		relative, err := filepath.Rel(template, path)
		if err != nil {
			return err
		}
		if strings.HasPrefix(relative, "requests"+string(filepath.Separator)) {
			return nil // Exercise the real captured requests, not example bytes.
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		write(t, filepath.Join(project, relative), data)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	run := filepath.Join(root, "campaign")
	code, out, stderr := call("flow", "test", "--project", project, "--base-url", base, "--out", run, "--json")
	if code != 3 || stderr != "" || gjson.Get(out, "result.baseline.outcome").String() != "pass" || gjson.Get(out, "result.cases.0.outcome").String() != "fail" || gjson.Get(out, "result.cases.1.outcome").String() != "pass" {
		t.Fatalf("campaign code=%d out=%s err=%s", code, out, stderr)
	}
	read := func(directory, name string) []byte {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(directory, name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	baseline := read(run, "baseline")
	negative := read(run, "negative")
	if gjson.GetBytes(negative, "trial.mutation_proof").String() != "verified" || gjson.GetBytes(negative, "flow.steps.3.sent.body.data.quantity").Int() != -10 || math.Abs(gjson.GetBytes(negative, "verification.steps.0.response.body.data.data.0.totalPrice").Float()+19.9) > 1e-9 {
		t.Fatal("negative case lacks proof of sent quantity -10 and persisted total -19.90")
	}
	replay := filepath.Join(root, "replay")
	code, out, stderr = call("flow", "replay", "--project", project, "--base-url", base, "--run", run, "--case", "negative", "--out", replay, "--json")
	if code != 3 || stderr != "" || gjson.Get(out, "result.cases.0.outcome").String() != "fail" {
		t.Fatalf("replay code=%d out=%s err=%s", code, out, stderr)
	}
	replayed := read(replay, "negative")
	accounts := map[int64]bool{}
	for _, record := range [][]byte{baseline, negative, read(run, "zero"), read(replay, "baseline"), replayed} {
		id := gjson.GetBytes(record, "flow.steps.0.response.body.data.data.id").Int()
		if id <= 0 || accounts[id] {
			t.Fatal("baseline, cases, and replay must create fresh accounts")
		}
		accounts[id] = true
		if strings.Contains(string(record), password) || strings.Contains(string(record), token) {
			t.Fatal("redacted evidence contains a password or captured token")
		}
	}
	if math.Abs(gjson.GetBytes(replayed, "verification.steps.0.response.body.data.data.0.totalPrice").Float()+19.9) > 1e-9 {
		t.Fatal("replay did not reproduce the persisted negative order")
	}
	t.Log("captured 6 requests; inferred 4 authorization links; baseline pass; negative fail (-19.90); zero pass; fresh-state replay fail (-19.90)")
}
