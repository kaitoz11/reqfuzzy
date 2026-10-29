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
		out.Steps = append(out.Steps, stepSummary{ID: step.StepID, Actor: step.Actor, Request: step.RequestName, Status: step.StatusCode, ResponseSHA: hash})
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
			fmt.Fprintf(stdout, "  %s  %s\n", step.ID, step.Request)
		}
		for _, edge := range value.Edges {
			fmt.Fprintf(stdout, "  %s -> %s  %s => %s:%s\n", edge.From, edge.To, edge.Variable, edge.Location, edge.Path)
		}
	case map[string]any:
		fmt.Fprintf(stdout, "Created project %s (%v requests)\n", value["project"], value["requests"])
	}
	return code
}
func printRun(out io.Writer, value runSummary) {
	fmt.Fprintln(out, value.FlowName)
	for _, step := range value.Steps {
		fmt.Fprintf(out, "  %s  HTTP %d  %s\n", step.ID, step.Status, step.ResponseSHA)
	}
	if value.FailedStepID != "" {
		fmt.Fprintf(out, "  failed step: %s\n", value.FailedStepID)
	}
}

type viewStep struct {
	ID            string `json:"id"`
	Request       string `json:"request"`
	Actor         string `json:"actor"`
	BeforeSend    string `json:"before_send,omitempty"`
	AfterResponse string `json:"after_response,omitempty"`
}
type edge struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Variable string `json:"variable"`
	Location string `json:"location"`
	Path     string `json:"path"`
}
type flowView struct {
	Name  string     `json:"name"`
	Steps []viewStep `json:"steps"`
	Edges []edge     `json:"edges"`
}

func view(definition flow.Flow) flowView {
	result := flowView{Name: definition.Name, Steps: []viewStep{}, Edges: []edge{}}
	sources := map[string]string{}
	for _, step := range definition.Steps {
		result.Steps = append(result.Steps, viewStep{ID: step.ID, Request: step.Request, Actor: step.Actor, BeforeSend: step.BeforeSend, AfterResponse: step.AfterResponse})
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
