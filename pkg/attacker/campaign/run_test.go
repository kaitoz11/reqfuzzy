package campaign_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/kaitoz11/reqfuzzy/internal/reference"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/campaign"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
)

func setup(t *testing.T, options reference.Options) (flow.Runner, flow.Flow, *flow.Flow, campaign.Spec) {
	t.Helper()
	server := httptest.NewServer(reference.NewHandler(options))
	t.Cleanup(server.Close)
	store := attacker.NewRequestStore()
	directory := t.TempDir()
	for name, raw := range map[string]string{"session": "POST /session HTTP/1.1\r\nHost: reference.test\r\n\r\n", "nonce": "GET /nonce HTTP/1.1\r\nHost: reference.test\r\n\r\n", "transfer": "POST /transfer HTTP/1.1\r\nHost: reference.test\r\nContent-Type: application/json\r\n\r\n{\"amount\":10,\"nonce\":\"stale\"}", "balance": "GET /balance HTTP/1.1\r\nHost: reference.test\r\n\r\n"} {
		path := filepath.Join(directory, name+".txt")
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		store.RegisterRequestFilePath(name, path)
	}
	source := `name: transfer
steps:
  - id: session
    request: session
    expect_status: 200
    extract:
      - {name: token, json: access_token}
      - {name: signing_key, json: signing_key}
      - {name: initial_balance, json: balance}
  - id: nonce
    request: nonce
    expect_status: 200
    bind: [{location: header, path: Authorization, variable: token, prefix: 'Bearer '}]
    extract: [{name: nonce, json: nonce}]
  - id: transfer
    request: transfer
    expect_status: 201
    bind:
      - {location: header, path: Authorization, variable: token, prefix: 'Bearer '}
      - {location: json, path: nonce, variable: nonce}
    before_send: sign
    extract: [{name: transaction_id, json: transaction_id}]
`
	main, err := flow.LoadYAML([]byte(source))
	if err != nil {
		t.Fatal(err)
	}
	verify, err := flow.LoadYAMLWithVariables([]byte("name: verify\nsteps:\n  - id: balance\n    request: balance\n    expect_status: 200\n    bind: [{location: header, path: Authorization, variable: token, prefix: 'Bearer '}]\n"), campaign.DeclaredVariables(main, nil))
	if err != nil {
		t.Fatal(err)
	}
	runner := flow.Runner{Store: store, NewClient: func(string) (*attacker.HClient, error) {
		client := attacker.NewHClient()
		client.UseBaseURL(server.URL)
		return client, nil
	}, BeforeSend: map[string]flow.BeforeSend{"sign": func(request attacker.Request, variables flow.Variables) error {
		mac := hmac.New(sha256.New, []byte(variables["signing_key"].Text))
		mac.Write(request.Body)
		request.SetHeader("X-Signature", hex.EncodeToString(mac.Sum(nil)))
		return nil
	}}}
	spec, err := campaign.LoadYAML([]byte(validTest))
	if err != nil {
		t.Fatal(err)
	}
	return runner, main, &verify, spec
}

func TestCampaignDistinguishesSecureAndVulnerableState(t *testing.T) {
	for _, vulnerable := range []bool{false, true} {
		t.Run(fmt.Sprint(vulnerable), func(t *testing.T) {
			runner, main, verify, spec := setup(t, reference.Options{VulnerableAmounts: vulnerable})
			var recorded []string
			result, err := campaign.Run(context.Background(), runner, main, verify, spec, campaign.Options{Record: func(trial campaign.Trial) error { recorded = append(recorded, trial.ID); return nil }})
			if err != nil {
				t.Fatal(err)
			}
			want := campaign.Pass
			if vulnerable {
				want = campaign.Fail
			}
			if result.Outcome != want || result.Baseline.Outcome != campaign.Pass || len(result.Cases) != 2 || len(recorded) != 3 {
				t.Fatalf("result=%#v recorded=%v", result, recorded)
			}
			negative := result.Cases[0]
			if negative.Outcome != want || len(negative.Verification.Steps) != 1 {
				t.Fatalf("rejection/violation not verified: %#v", negative)
			}
			if vulnerable {
				if string(negative.Checks[0].Actual) != "110" || string(negative.Checks[0].Expected) != "100" {
					t.Fatalf("wrong invariant operands: %#v", negative.Checks)
				}
			} else if negative.TargetStatus != 422 {
				t.Fatalf("secure mutation not rejected: %#v", negative)
			}
			nonces := map[string]bool{}
			for _, trial := range append([]campaign.Trial{result.Baseline}, result.Cases...) {
				nonce := trial.Flow.Variables["nonce"].Text
				if nonce == "" || nonces[nonce] {
					t.Fatal("nonce/session reused across trials")
				}
				nonces[nonce] = true
			}
		})
	}
}

func TestInvalidAuthenticationIsInconclusive(t *testing.T) {
	runner, main, verify, spec := setup(t, reference.Options{})
	spec.Target.Location = "header"
	spec.Target.Path = "Authorization"
	spec.Cases = []campaign.Case{{ID: "expired", Action: "set", Value: campaign.Scalar(`"Bearer invalid"`)}}
	result, err := campaign.Run(context.Background(), runner, main, verify, spec, campaign.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Baseline.Outcome != campaign.Pass || result.Outcome != campaign.Inconclusive || len(result.Cases) != 1 || result.Cases[0].TargetStatus != 401 {
		t.Fatalf("auth failure became pass/finding: %#v", result)
	}
}

func TestInvalidBaselineStopsCases(t *testing.T) {
	runner, main, verify, spec := setup(t, reference.Options{ExpireAtTransfer: true})
	result, err := campaign.Run(context.Background(), runner, main, verify, spec, campaign.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != campaign.Inconclusive || len(result.Cases) != 0 {
		t.Fatalf("mutations ran without valid baseline: %#v", result)
	}
}

func TestEvidenceFailureStopsBeforeFurtherTrials(t *testing.T) {
	runner, main, verify, spec := setup(t, reference.Options{})
	result, err := campaign.Run(context.Background(), runner, main, verify, spec, campaign.Options{Record: func(campaign.Trial) error { return fmt.Errorf("disk full") }})
	if err == nil || len(result.Cases) != 0 {
		t.Fatalf("continued without evidence: %#v %v", result, err)
	}
}

func TestLaterEvidenceFailureDoesNotReportCompletedPass(t *testing.T) {
	runner, main, verify, spec := setup(t, reference.Options{})
	records := 0
	result, err := campaign.Run(context.Background(), runner, main, verify, spec, campaign.Options{Record: func(campaign.Trial) error {
		records++
		if records == 2 {
			return fmt.Errorf("disk full")
		}
		return nil
	}})
	if err == nil || len(result.Cases) != 1 || records != 2 || result.Outcome != campaign.Inconclusive {
		t.Fatalf("partial run reported completion: outcome=%s cases=%d err=%v records=%d", result.Outcome, len(result.Cases), err, records)
	}
}

func TestHookErasedMutationIsInconclusive(t *testing.T) {
	runner, main, verify, spec := setup(t, reference.Options{})
	spec.Target.Location = "header"
	spec.Target.Path = "X-Signature"
	spec.Cases = []campaign.Case{{ID: "invalid-signature", Action: "set", Value: campaign.Scalar(`"invalid"`)}}
	result, err := campaign.Run(context.Background(), runner, main, verify, spec, campaign.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != campaign.Inconclusive || len(result.Cases) != 1 || result.Cases[0].Outcome != campaign.Inconclusive {
		t.Fatalf("erased mutation was treated as a valid test: outcome=%s cases=%d", result.Outcome, len(result.Cases))
	}
}
