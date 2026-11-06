package cli

import (
	"flag"
	"fmt"
	"io"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/campaign"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
)

type planCase struct {
	ID          string `json:"id"`
	Action      string `json:"action"`
	Source      string `json:"source,omitempty"`
	SourceIndex int    `json:"source_index,omitempty"`
}
type payloadPlanSummary struct {
	Name              string          `json:"name"`
	Target            campaign.Target `json:"target"`
	Cases             []planCase      `json:"cases"`
	RequestUpperBound int64           `json:"request_upper_bound"`
	WithinBudget      bool            `json:"within_budget"`
	InputCount        int             `json:"input_count"`
}

func runPayloadPlan(args []string, stdout, stderr io.Writer, jsonMode bool) int {
	flags := flag.NewFlagSet("flow plan", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.BoolVar(&jsonMode, "json", jsonMode, "JSON summary")
	directory := flags.String("project", ".", "project directory")
	testFile := flags.String("test", "tests.yaml", "test definition")
	hooks := flags.String("hooks", "", "explicit script directory")
	maxRequests := flags.Int64("max-requests", 1000, "planned budget")
	fail := func(err error) int { return emit(stdout, stderr, jsonMode, "flow plan", nil, 1, err) }
	if err := flags.Parse(args); err != nil {
		return fail(err)
	}
	if flags.NArg() != 0 || *maxRequests < 1 {
		return fail(fmt.Errorf("flow plan requires a positive budget and no positional arguments"))
	}
	loaded, err := loadJourneyProject(*directory, *testFile, *hooks)
	if err != nil {
		return fail(err)
	}
	if err := validateTargets(loaded.project, loaded.additional()...); err != nil {
		return fail(err)
	}
	runner := flow.Runner{Store: loaded.project.Store, NewClient: func(string) (*attacker.HClient, error) { return nil, fmt.Errorf("planning is offline") }, BeforeSend: map[string]flow.BeforeSend{}, AfterResponse: map[string]flow.AfterResponse{}}
	for _, definition := range append([]flow.Flow{loaded.project.Flow}, loaded.additional()...) {
		for _, step := range definition.Steps {
			if step.BeforeSend != "" {
				runner.BeforeSend[step.BeforeSend] = func(attacker.Request, flow.Variables) error { return nil }
			}
			if step.AfterResponse != "" {
				runner.AfterResponse[step.AfterResponse] = func(attacker.Response, flow.Variables) error { return nil }
			}
		}
	}
	if err := campaign.Preflight(runner, loaded.project.Flow, loaded.verification, loaded.spec); err != nil {
		return fail(err)
	}
	bound, err := campaign.RequestUpperBound(loaded.project.Flow, loaded.verification, len(loaded.spec.Cases))
	if err != nil {
		return fail(err)
	}
	summary := payloadPlanSummary{Name: loaded.spec.Name, Target: loaded.spec.Target, Cases: []planCase{}, RequestUpperBound: bound, WithinBudget: bound <= *maxRequests, InputCount: len(loaded.files)}
	for _, candidate := range loaded.spec.Cases {
		summary.Cases = append(summary.Cases, planCase{candidate.ID, candidate.Action, candidate.Source, candidate.SourceIndex})
	}
	return emit(stdout, stderr, jsonMode, "flow plan", summary, 0, nil)
}
