package campaign_test

import (
	"testing"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker/campaign"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
)

func trial(body string) campaign.Trial {
	return campaign.Trial{Flow: flow.RunResult{Steps: []flow.StepResult{{StepID: "observe", StatusCode: 200, ResponseBody: []byte(body)}}, Variables: flow.Variables{}}}
}

func TestExactNumericAndBaselineChecks(t *testing.T) {
	baseline := trial(`{"number":9007199254740992,"result":"same","nonce":"first"}`)
	changed := trial(`{"number":9007199254740993,"result":"same","nonce":"second"}`)
	check := campaign.Check{ID: "exact", Phase: "flow", Step: "observe", Select: "json", Path: "number", Op: "lte", Value: campaign.Scalar("9007199254740992")}
	if got := campaign.EvaluateCheck(check, changed, baseline); got.Outcome != campaign.Fail {
		t.Fatalf("rounded numeric check: %#v", got)
	}
	check = campaign.Check{ID: "stable-field", Phase: "flow", Step: "observe", Select: "json", Path: "result", Op: "eq", Baseline: true}
	if got := campaign.EvaluateCheck(check, changed, baseline); got.Outcome != campaign.Pass {
		t.Fatalf("volatile field caused false difference: %#v", got)
	}
	check.Path = "missing"
	if got := campaign.EvaluateCheck(check, changed, baseline); got.Outcome != campaign.Inconclusive {
		t.Fatalf("missing observation was assessable: %#v", got)
	}
}

func TestCheckUsesTrialStateRatherThanBaselineState(t *testing.T) {
	changed := trial(`{"balance":110}`)
	initial, _ := flow.ParseValue([]byte("100"))
	changed.Flow.Variables["initial_balance"] = initial
	check := campaign.Check{ID: "invariant", Step: "observe", Select: "json", Path: "balance", Op: "lte", Variable: "initial_balance"}
	got := campaign.EvaluateCheck(check, changed, trial(`{"balance":90}`))
	if got.Outcome != campaign.Fail || string(got.Expected) != "100" {
		t.Fatalf("invariant=%#v", got)
	}
	check.Variable = "absent"
	if got := campaign.EvaluateCheck(check, changed, changed); got.Outcome != campaign.Inconclusive {
		t.Fatal("missing variable passed")
	}
}

func TestBooleanChecksUseJSONBooleanType(t *testing.T) {
	changed := trial(`{"allowed":false}`)
	check := campaign.Check{ID: "allowed", Step: "observe", Select: "json", Path: "allowed", Op: "eq", Value: campaign.Scalar("true")}
	if got := campaign.EvaluateCheck(check, changed, changed); got.Outcome != campaign.Fail {
		t.Fatalf("false eq true: %#v", got)
	}
	check.Op = "ne"
	if got := campaign.EvaluateCheck(check, changed, changed); got.Outcome != campaign.Pass {
		t.Fatalf("false ne true: %#v", got)
	}
}

func TestDuplicateJSONObservationIsInconclusive(t *testing.T) {
	changed := trial(`{"balance":90,"balance":110}`)
	check := campaign.Check{ID: "balance", Step: "observe", Select: "json", Path: "balance", Op: "lte", Value: campaign.Scalar("100")}
	if got := campaign.EvaluateCheck(check, changed, changed); got.Outcome != campaign.Inconclusive {
		t.Fatalf("ambiguous observation accepted: %#v", got)
	}
}
