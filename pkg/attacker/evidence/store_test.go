package evidence_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker/campaign"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/evidence"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
)

func TestPrivateEvidenceRedactsMessagesAndPreservesProvenance(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "test.yaml")
	if err := os.WriteFile(input, []byte("secret source"), 0600); err != nil {
		t.Fatal(err)
	}
	hashes, err := evidence.Fingerprint(map[string]string{"test": input})
	if err != nil {
		t.Fatal(err)
	}
	recipe := evidence.Recipe{FormatVersion: 1, TestPath: "tests.yaml", Inputs: hashes, Cases: []string{"negative"}, BaseURL: "http://reference.test"}
	directory := filepath.Join(root, "run")
	store, err := evidence.NewStore(directory, recipe, campaign.Redaction{JSONPaths: []string{"customer.account"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	message := flow.RequestSnapshot{Method: "POST", RawURL: "http://reference.test/transfer?token=secret123&id=42", Host: "reference.test", Headers: http.Header{"Authorization": []string{"Bearer secret123"}, "Cookie": []string{"sid=cookie-session"}, "X-API-Key": []string{"api-key-value"}, "X-Signature": []string{"signature-value"}}, Body: []byte(`{"token":"secret123","balance":110,"customer":{"account":"hidden-account"}}`)}
	trial := campaign.Trial{ID: "baseline", Outcome: campaign.Pass, Flow: flow.RunResult{FlowName: "reference", Steps: []flow.StepResult{{StepID: "transfer", Request: message, SentRequest: &message, StatusCode: 201, ResponseHeaders: http.Header{"Set-Cookie": []string{"sid=cookie-session"}}, ResponseBody: message.Body}}}}
	if err := store.Record(trial); err != nil {
		t.Fatal(err)
	}
	if err := store.Finish(campaign.Result{Name: "reference", Outcome: campaign.Pass, Baseline: trial}, nil); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"plan.json", "baseline.json", "result.json"} {
		data, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{"secret123", "cookie-session", "hidden-account", "secret source", "api-key-value", "signature-value"} {
			if strings.Contains(string(data), secret) {
				t.Fatalf("%s leaked %q", name, secret)
			}
		}
		info, _ := os.Stat(filepath.Join(directory, name))
		if info.Mode().Perm() != 0600 {
			t.Fatal("evidence permissions not private")
		}
	}
	data, _ := os.ReadFile(filepath.Join(directory, "baseline.json"))
	if !strings.Contains(string(data), "110") || !strings.Contains(string(data), "[REDACTED]") {
		t.Fatalf("redacted structure unavailable: %s", data)
	}
	if err := store.Record(trial); err == nil {
		t.Fatal("trial artifact overwritten")
	}
	if _, err := evidence.NewStore(directory, recipe, campaign.Redaction{}, false); err == nil {
		t.Fatal("existing run replaced")
	}
	loaded, err := evidence.ReadRecipe(directory)
	if err != nil || loaded.Inputs["test"] != hashes["test"] {
		t.Fatalf("recipe=%#v err=%v", loaded, err)
	}
	if err := os.WriteFile(input, []byte("changed source"), 0600); err != nil {
		t.Fatal(err)
	}
	current, _ := evidence.Fingerprint(map[string]string{"test": input})
	if err := evidence.VerifyInputs(loaded.Inputs, current); err == nil {
		t.Fatal("input drift accepted")
	}
}

func TestSensitiveEvidenceKeepsExactBodyBytes(t *testing.T) {
	store, err := evidence.NewStore(filepath.Join(t.TempDir(), "run"), evidence.Recipe{FormatVersion: 1, TestPath: "tests.yaml", Inputs: map[string]string{"test": strings.Repeat("a", 64)}, Cases: []string{"one"}, BaseURL: "http://reference.test"}, campaign.Redaction{}, true)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte{0, 10, 255}
	trial := campaign.Trial{ID: "one", Flow: flow.RunResult{Steps: []flow.StepResult{{StepID: "one", ResponseBody: body, StatusCode: 200}}}}
	if err := store.Record(trial); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(store.Directory(), "one.json"))
	if err != nil {
		t.Fatal(err)
	}
	var artifact struct {
		Flow struct {
			Steps []struct {
				Response struct {
					Body struct {
						Encoding string `json:"encoding"`
						Data     string `json:"data"`
					} `json:"body"`
				} `json:"response"`
			} `json:"steps"`
		} `json:"flow"`
	}
	if err := json.Unmarshal(data, &artifact); err != nil {
		t.Fatal(err)
	}
	got, err := base64.StdEncoding.DecodeString(artifact.Flow.Steps[0].Response.Body.Data)
	if err != nil || string(got) != string(body) || artifact.Flow.Steps[0].Response.Body.Encoding != "base64" {
		t.Fatalf("raw body corrupted: %s %v", data, err)
	}
}

func TestDefaultEvidenceOmitsAmbiguousDuplicateJSONBody(t *testing.T) {
	store, err := evidence.NewStore(filepath.Join(t.TempDir(), "run"), evidence.Recipe{FormatVersion: 1, TestPath: "tests.yaml", Inputs: map[string]string{"test": strings.Repeat("a", 64)}, Cases: []string{"one"}, BaseURL: "http://reference.test"}, campaign.Redaction{JSONPaths: []string{"account"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	trial := campaign.Trial{ID: "one", Flow: flow.RunResult{Steps: []flow.StepResult{{StepID: "one", StatusCode: 200, ResponseBody: []byte(`{"account":"first-secret","account":"last-secret"}`)}}}}
	if err := store.Record(trial); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(store.Directory(), "one.json"))
	if strings.Contains(string(data), "last-secret") || strings.Contains(string(data), "first-secret") {
		t.Fatalf("ambiguous redaction leaked body: %s", data)
	}
}

func TestUnsupportedMatchingRedactionPathOmitsBody(t *testing.T) {
	store, err := evidence.NewStore(filepath.Join(t.TempDir(), "run"), evidence.Recipe{FormatVersion: 1, TestPath: "tests.yaml", Inputs: map[string]string{"test": strings.Repeat("a", 64)}, Cases: []string{"one"}, BaseURL: "http://reference.test"}, campaign.Redaction{JSONPaths: []string{"items.#.account"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	trial := campaign.Trial{ID: "one", Flow: flow.RunResult{Steps: []flow.StepResult{{StepID: "one", StatusCode: 200, ResponseBody: []byte(`{"items":[{"account":"hidden-account"}]}`)}}}}
	if err := store.Record(trial); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(store.Directory(), "one.json"))
	if strings.Contains(string(data), "hidden-account") {
		t.Fatalf("unapplied configured redaction leaked: %s", data)
	}
}

func TestPipeRedactionCannotSilentlyLeaveOriginalValue(t *testing.T) {
	for _, path := range []string{"items|0.account", "items.0.account|@this"} {
		store, err := evidence.NewStore(filepath.Join(t.TempDir(), "run"), evidence.Recipe{FormatVersion: 1, TestPath: "tests.yaml", Inputs: map[string]string{"test": strings.Repeat("a", 64)}, Cases: []string{"one"}, BaseURL: "http://reference.test"}, campaign.Redaction{JSONPaths: []string{path}}, false)
		if err != nil {
			t.Fatal(err)
		}
		trial := campaign.Trial{ID: "one", Flow: flow.RunResult{Steps: []flow.StepResult{{StepID: "one", StatusCode: 200, ResponseBody: []byte(`{"items":[{"account":"hidden-account"}]}`)}}}}
		if err := store.Record(trial); err != nil {
			t.Fatal(err)
		}
		data, _ := os.ReadFile(filepath.Join(store.Directory(), "one.json"))
		if strings.Contains(string(data), "hidden-account") {
			t.Fatalf("redaction %q leaked original value", path)
		}
	}
}
