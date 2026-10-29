package campaign

import (
	"context"
	"errors"
	"fmt"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
)

type Options struct{ Record func(Trial) error }

func Preflight(runner flow.Runner, main flow.Flow, verification *flow.Flow, spec Spec) error {
	if err := Validate(spec); err != nil {
		return err
	}
	if err := runner.Preflight(main); err != nil {
		return err
	}
	targetFound := false
	mainSteps := map[string]bool{}
	for _, step := range main.Steps {
		mainSteps[step.ID] = true
		if step.ID == spec.Target.Step {
			targetFound = true
			if step.ExpectStatus != nil && !observed(spec, *step.ExpectStatus) {
				return fmt.Errorf("baseline target expectation is outside observe_statuses")
			}
		}
	}
	if !targetFound {
		return fmt.Errorf("test target step does not exist")
	}
	declared := DeclaredVariables(main, runner.InitialVariables)
	verifySteps := map[string]bool{}
	if spec.Verify != "" && verification == nil {
		return fmt.Errorf("test requires its verification flow")
	}
	if verification != nil {
		verifyRunner := runner
		verifyRunner.InitialVariables = declared
		if err := verifyRunner.Preflight(*verification); err != nil {
			return fmt.Errorf("verification preflight: %w", err)
		}
		declared = DeclaredVariables(*verification, declared)
		for _, step := range verification.Steps {
			verifySteps[step.ID] = true
		}
	}
	for _, check := range spec.Checks {
		steps := mainSteps
		if check.Phase == "verify" {
			steps = verifySteps
		}
		if !steps[check.Step] {
			return fmt.Errorf("check %q refers to an unknown step", check.ID)
		}
		if check.Variable != "" {
			if _, exists := declared[check.Variable]; !exists {
				return fmt.Errorf("check %q refers to an undeclared variable", check.ID)
			}
		}
	}
	return nil
}

func Run(ctx context.Context, runner flow.Runner, main flow.Flow, verification *flow.Flow, spec Spec, options Options) (Result, error) {
	result := Result{Name: spec.Name, Outcome: Inconclusive, Cases: []Trial{}}
	if err := Preflight(runner, main, verification, spec); err != nil {
		return result, err
	}
	mutations := make([]flow.Mutation, len(spec.Cases))
	for index, candidate := range spec.Cases {
		mutations[index], _ = flow.BuildMutation(flow.MutationSpec{Action: candidate.Action, Location: spec.Target.Location, Path: spec.Target.Path, Value: candidate.Value})
	}
	baseline := executeTrial(ctx, runner, main, verification, spec, "baseline", nil, true, "")
	if baseline.Outcome == Pass {
		baseline.Checks = evaluate(spec.Checks, baseline, baseline)
		baseline.Outcome = checksOutcome(baseline.Checks)
		if baseline.Outcome != Pass {
			baseline.Outcome = Inconclusive
			baseline.Reason = "baseline does not satisfy the configured checks"
		}
	}
	result.Baseline = baseline
	if options.Record != nil {
		if err := options.Record(baseline); err != nil {
			result.Outcome = Inconclusive
			return result, err
		}
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if baseline.Outcome != Pass {
		return result, nil
	}
	result.Outcome = Pass
	for index, candidate := range spec.Cases {
		if err := ctx.Err(); err != nil {
			result.Outcome = Inconclusive
			return result, err
		}
		trial := executeTrial(ctx, runner, main, verification, spec, candidate.ID, &flow.StepMutation{StepID: spec.Target.Step, Apply: mutations[index]}, false, candidate.Action)
		if trial.Outcome == Pass {
			trial.Checks = evaluate(spec.Checks, trial, baseline)
			trial.Outcome = checksOutcome(trial.Checks)
		}
		result.Cases = append(result.Cases, trial)
		if trial.Outcome == Fail {
			result.Outcome = Fail
		} else if trial.Outcome == Inconclusive && result.Outcome != Fail {
			result.Outcome = Inconclusive
		}
		if options.Record != nil {
			if err := options.Record(trial); err != nil {
				result.Outcome = Inconclusive
				return result, err
			}
		}
		if err := ctx.Err(); err != nil {
			result.Outcome = Inconclusive
			return result, err
		}
	}
	return result, nil
}

func executeTrial(ctx context.Context, runner flow.Runner, main flow.Flow, verification *flow.Flow, spec Spec, id string, mutation *flow.StepMutation, baseline bool, action string) Trial {
	trial := Trial{ID: id, Outcome: Inconclusive, Checks: []CheckResult{}}
	// A trial has one fresh actor cache; main and verification reuse its sessions.
	original := runner.NewClient
	clients := map[string]*attacker.HClient{}
	defer func() {
		for _, client := range clients {
			if client != nil {
				client.CloseIdleConnections()
			}
		}
	}()
	runner.NewClient = func(actor string) (*attacker.HClient, error) {
		if client := clients[actor]; client != nil {
			return client, nil
		}
		client, err := original(actor)
		if err == nil {
			clients[actor] = client
		}
		return client, err
	}
	var runErr error
	trial.Flow, runErr = runner.Run(ctx, main, mutation)
	for _, step := range trial.Flow.Steps {
		if step.StepID == spec.Target.Step {
			trial.TargetStatus = step.StatusCode
			break
		}
	}
	if baseline && runErr != nil {
		trial.Reason = "baseline main flow did not complete"
		executionError(&trial, runErr)
		return trial
	}
	if !observed(spec, trial.TargetStatus) {
		trial.Reason = "target response is outside observe_statuses"
		executionError(&trial, runErr)
		return trial
	}
	if runErr != nil {
		var stepErr *flow.StepError
		if !errors.As(runErr, &stepErr) || stepErr.StepID != spec.Target.Step || (stepErr.Kind != flow.StatusError && stepErr.Kind != flow.ExtractionError) {
			trial.Reason = "main flow failed outside an assessable target response"
			executionError(&trial, runErr)
			return trial
		}
		executionError(&trial, runErr)
	}
	if mutation != nil {
		proof, ok := mutationSurvived(trial.Flow, spec.Target, action)
		trial.MutationProof = proof
		if !ok {
			trial.Reason = "target mutation was overwritten or its sent value cannot be verified"
			return trial
		}
	}
	if verification != nil {
		runner.InitialVariables = trial.Flow.Variables
		trial.Verification, runErr = runner.Run(ctx, *verification, nil)
		if runErr != nil {
			trial.Reason = "verification flow did not complete"
			executionError(&trial, runErr)
			return trial
		}
	}
	trial.Outcome = Pass
	return trial
}

func executionError(trial *Trial, err error) {
	var stepErr *flow.StepError
	if errors.As(err, &stepErr) {
		trial.ErrorKind = stepErr.Kind
		trial.FailedStep = stepErr.StepID
	}
}
func observed(spec Spec, status int) bool {
	for _, accepted := range spec.ObserveStatuses {
		if accepted == status {
			return true
		}
	}
	return false
}
func evaluate(checks []Check, trial, baseline Trial) []CheckResult {
	results := make([]CheckResult, 0, len(checks))
	for _, check := range checks {
		results = append(results, EvaluateCheck(check, trial, baseline))
	}
	return results
}
func checksOutcome(checks []CheckResult) Outcome {
	result := Pass
	for _, check := range checks {
		if check.Outcome == Inconclusive {
			return Inconclusive
		}
		if check.Outcome == Fail {
			result = Fail
		}
	}
	return result
}
