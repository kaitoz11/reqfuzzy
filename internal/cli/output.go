package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
)

type errorInfo struct {
	Kind    string `json:"kind"`
	StepID  string `json:"step_id,omitempty"`
	Message string `json:"message"`
}
type envelope struct {
	FormatVersion int        `json:"format_version"`
	Command       string     `json:"command"`
	Result        any        `json:"result,omitempty"`
	Error         *errorInfo `json:"error,omitempty"`
}
type stepSummary struct {
	ID          string `json:"id"`
	Visit       int    `json:"visit,omitempty"`
	NextStep    string `json:"next_step,omitempty"`
	Control     string `json:"control_source,omitempty"`
	Actor       string `json:"actor"`
	Request     string `json:"request"`
	Status      int    `json:"status"`
	ResponseSHA string `json:"response_sha256,omitempty"`
}
type runSummary struct {
	FlowName     string        `json:"flow_name"`
	Steps        []stepSummary `json:"steps"`
	FailedStepID string        `json:"failed_step_id,omitempty"`
}
type comparisonSummary struct {
	MutationStepID string     `json:"mutation_step_id"`
	Baseline       runSummary `json:"baseline"`
	Mutated        runSummary `json:"mutated"`
}

func summary(result flow.RunResult) runSummary {
	out := runSummary{FlowName: result.FlowName, FailedStepID: result.FailedStepID, Steps: make([]stepSummary, 0, len(result.Steps))}
	for _, step := range result.Steps {
		hash := ""
		if step.StatusCode != 0 {
			digest := sha256.Sum256(step.ResponseBody)
			hash = hex.EncodeToString(digest[:])
		}
		out.Steps = append(out.Steps, stepSummary{ID: step.StepID, Visit: step.Visit, NextStep: step.NextStepID, Control: step.ControlSource, Actor: step.Actor, Request: step.RequestName, Status: step.StatusCode, ResponseSHA: hash})
	}
	return out
}

func emit(stdout, stderr io.Writer, jsonMode bool, command string, result any, code int, err error) int {
	var info *errorInfo
	if err != nil {
		info = &errorInfo{Kind: "configuration", Message: err.Error()}
		if code == 2 {
			info.Kind = "execution"
		}
		var stepErr *flow.StepError
		if errors.As(err, &stepErr) {
			info.Kind = string(stepErr.Kind)
			info.StepID = stepErr.StepID
			if stepErr.Kind == flow.TransportError {
				info.Message = "request transport failed"
				if errors.Is(err, context.DeadlineExceeded) {
					info.Message = "request deadline exceeded"
				} else if errors.Is(err, context.Canceled) {
					info.Message = "request canceled"
				}
			}
		}
	}
	if jsonMode {
		if encodeErr := json.NewEncoder(stdout).Encode(envelope{FormatVersion: 1, Command: command, Result: result, Error: info}); encodeErr != nil {
			fmt.Fprintln(stderr, encodeErr)
			return 1
		}
		return code
	}
	if err != nil {
		fmt.Fprintf(stderr, "%s", info.Message)
		if info.StepID != "" {
			fmt.Fprintf(stderr, " (step %s)", info.StepID)
		}
		fmt.Fprintln(stderr)
	}
	switch value := result.(type) {
	case mapSummary:
		fmt.Fprintf(stdout, "Wrote flow map %s (%d steps, %d dependencies)\n", value.File, value.Steps, value.Dependencies)
	case testSummary:
		fmt.Fprintf(stdout, "%s: %s\n", value.Name, value.Outcome)
		fmt.Fprintf(stdout, "  baseline: %s\n", value.Baseline.Outcome)
		for _, trial := range value.Cases {
			fmt.Fprintf(stdout, "  %s: %s", trial.ID, trial.Outcome)
			if trial.Reason != "" {
				fmt.Fprintf(stdout, " (%s)", trial.Reason)
			}
			fmt.Fprintln(stdout)
			for _, check := range trial.Checks {
				fmt.Fprintf(stdout, "    %s: %s\n", check.ID, check.Outcome)
			}
		}
		fmt.Fprintf(stdout, "  evidence: %s\n", value.ArtifactsDir)
	case runSummary:
		printRun(stdout, value)
	case comparisonSummary:
		fmt.Fprintln(stdout, "Baseline:")
		printRun(stdout, value.Baseline)
		fmt.Fprintln(stdout, "Mutated:")
		printRun(stdout, value.Mutated)
	case flowView:
		fmt.Fprintln(stdout, value.Name)
		for _, step := range value.Steps {
			fmt.Fprintf(stdout, "  %s  %s", step.ID, step.Request)
			if step.MaxVisits > 1 {
				fmt.Fprintf(stdout, " (up to %d visits)", step.MaxVisits)
			}
			if step.ExpectStatus != nil {
				fmt.Fprintf(stdout, " (HTTP %d)", *step.ExpectStatus)
			} else if len(step.ExpectStatuses) > 0 {
				fmt.Fprintf(stdout, " (HTTP %v)", step.ExpectStatuses)
			}
			fmt.Fprintln(stdout)
		}
		for _, edge := range value.Edges {
			fmt.Fprintf(stdout, "  %s -> %s  %s => %s:%s\n", edge.From, edge.To, edge.Variable, edge.Location, edge.Path)
		}
		for _, control := range value.Controls {
			if control.Kind != "order" {
				target := control.To
				if target == "" {
					target = "end"
				}
				fmt.Fprintf(stdout, "  %s --%s--> %s\n", control.From, control.Kind, target)
			}
		}
	case map[string]any:
		fmt.Fprintf(stdout, "Created project %s (%v requests)\n", value["project"], value["requests"])
	}
	return code
}
func printRun(out io.Writer, value runSummary) {
	fmt.Fprintln(out, value.FlowName)
	for _, step := range value.Steps {
		label := step.ID
		if step.Visit > 1 {
			label += fmt.Sprintf(" (visit %d)", step.Visit)
		}
		fmt.Fprintf(out, "  %s  HTTP %d  %s", label, step.Status, step.ResponseSHA)
		if step.Control != "" && step.Control != "order" {
			if step.NextStep == "" {
				fmt.Fprint(out, " -> end")
			} else {
				fmt.Fprintf(out, " -> %s", step.NextStep)
			}
		}
		fmt.Fprintln(out)
	}
	if value.FailedStepID != "" {
		fmt.Fprintf(out, "  failed step: %s\n", value.FailedStepID)
	}
}

type viewStep struct {
	ID             string   `json:"id"`
	Request        string   `json:"request"`
	Actor          string   `json:"actor"`
	BeforeSend     string   `json:"before_send,omitempty"`
	AfterResponse  string   `json:"after_response,omitempty"`
	MaxVisits      int      `json:"max_visits,omitempty"`
	Next           *string  `json:"next,omitempty"`
	Routes         []string `json:"routes,omitempty"`
	ExpectStatus   *int     `json:"expect_status,omitempty"`
	ExpectStatuses []int    `json:"expect_statuses,omitempty"`
}

type controlEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"`
}
type edge struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Variable string `json:"variable"`
	Location string `json:"location"`
	Path     string `json:"path"`
}
type flowView struct {
	Name     string        `json:"name"`
	Steps    []viewStep    `json:"steps"`
	Edges    []edge        `json:"edges"`
	Controls []controlEdge `json:"controls,omitempty"`
}

func view(definition flow.Flow) flowView {
	result := flowView{Name: definition.Name, Steps: []viewStep{}, Edges: []edge{}}
	sources := map[string]string{}
	for index, step := range definition.Steps {
		result.Steps = append(result.Steps, viewStep{ID: step.ID, Request: step.Request, Actor: step.Actor, BeforeSend: step.BeforeSend, AfterResponse: step.AfterResponse, MaxVisits: flow.VisitLimit(step), Next: step.Next, Routes: step.Routes, ExpectStatus: step.ExpectStatus, ExpectStatuses: step.ExpectStatuses})
		next, kind := "", "order"
		if index+1 < len(definition.Steps) {
			next = definition.Steps[index+1].ID
		}
		if step.Next != nil {
			next, kind = *step.Next, "next"
		}
		result.Controls = append(result.Controls, controlEdge{step.ID, next, kind})
		for _, target := range step.Routes {
			result.Controls = append(result.Controls, controlEdge{step.ID, target, "route"})
		}
		for _, binding := range step.Bind {
			result.Edges = append(result.Edges, edge{From: sources[binding.Variable], To: step.ID, Variable: binding.Variable, Location: binding.Location, Path: binding.Path})
		}
		for _, extract := range step.Extract {
			sources[extract.Name] = step.ID
		}
		for _, name := range step.Provides {
			sources[name] = step.ID
		}
	}
	return result
}
