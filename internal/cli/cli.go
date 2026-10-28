package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/script"
)

func Run(args []string, stdout, stderr io.Writer) int {
	return RunContext(context.Background(), args, stdout, stderr)
}
func RunContext(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	jsonMode := false
	for _, arg := range args {
		if arg == "--json" || arg == "-json" || arg == "--json=true" {
			jsonMode = true
		}
	}
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(stdout, "reqfuzzy import --out DIR [--origin URL] HAR\nreqfuzzy flow show --project DIR [--json]\nreqfuzzy flow run --project DIR --base-url URL [--json]\nreqfuzzy flow compare --project DIR --base-url URL --step ID --location json|header|query --path KEY --value VALUE [--json]")
		return 0
	}
	command := args[0]
	if command == "flow" {
		if len(args) < 2 {
			return emit(stdout, stderr, jsonMode, "flow", nil, 1, fmt.Errorf("flow requires show, run, or compare"))
		}
		command += " " + args[1]
		args = args[2:]
	} else {
		args = args[1:]
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.BoolVar(&jsonMode, "json", jsonMode, "machine-readable output")
	directory := flags.String("project", ".", "project directory")
	if command == "import" {
		out := flags.String("out", "", "new project directory")
		selected := flags.String("origin", "", "capture origin")
		if err := flags.Parse(args); err != nil {
			return emit(stdout, stderr, jsonMode, command, nil, 1, err)
		}
		if *out == "" || flags.NArg() != 1 {
			return emit(stdout, stderr, jsonMode, command, nil, 1, fmt.Errorf("import requires --out DIR and one HAR file"))
		}
		result, err := importProject(flags.Arg(0), *out, *selected)
		code := 0
		if err != nil {
			code = 1
		}
		return emit(stdout, stderr, jsonMode, command, result, code, err)
	}
	if command != "flow show" && command != "flow run" && command != "flow compare" {
		return emit(stdout, stderr, jsonMode, command, nil, 1, fmt.Errorf("unknown command %q", command))
	}
	base := flags.String("base-url", "", "explicit replay target")
	hooks := flags.String("hooks", "", "hook directory (default project/hooks)")
	timeout := flags.Duration("timeout", 30*time.Second, "whole execution deadline")
	scriptTimeout := flags.Duration("script-timeout", time.Second, "each JS invocation deadline")
	step := flags.String("step", "", "mutation step")
	location := flags.String("location", "", "mutation location")
	path := flags.String("path", "", "mutation path")
	value := flags.String("value", "", "mutation value")
	if err := flags.Parse(args); err != nil {
		return emit(stdout, stderr, jsonMode, command, nil, 1, err)
	}
	if flags.NArg() != 0 {
		return emit(stdout, stderr, jsonMode, command, nil, 1, fmt.Errorf("unexpected positional arguments"))
	}
	project, err := loadProject(*directory)
	if err != nil {
		return emit(stdout, stderr, jsonMode, command, nil, 1, err)
	}
	if command == "flow show" {
		return emit(stdout, stderr, jsonMode, command, view(project.Flow), 0, nil)
	}
	target, err := url.Parse(*base)
	if err != nil || target.Host == "" || (target.Scheme != "http" && target.Scheme != "https") || target.User != nil || target.RawQuery != "" || target.Fragment != "" {
		return emit(stdout, stderr, jsonMode, command, nil, 1, fmt.Errorf("run and compare require an HTTP(S) --base-url without credentials, query, or fragment"))
	}
	if *timeout <= 0 || *scriptTimeout <= 0 {
		return emit(stdout, stderr, jsonMode, command, nil, 1, fmt.Errorf("timeouts must be positive"))
	}
	execution, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	before, after, err := loadScripts(execution, project, *hooks, *scriptTimeout)
	if err != nil {
		if execution.Err() != nil {
			return emit(stdout, stderr, jsonMode, command, nil, 2, execution.Err())
		}
		return emit(stdout, stderr, jsonMode, command, nil, 1, err)
	}
	var mutation flow.StepMutation
	if command == "flow compare" {
		found := false
		for _, candidate := range project.Flow.Steps {
			if candidate.ID == *step {
				found = true
				break
			}
		}
		if !found {
			return emit(stdout, stderr, jsonMode, command, nil, 1, fmt.Errorf("compare requires a valid --step"))
		}
		valueProvided := false
		flags.Visit(func(f *flag.Flag) {
			if f.Name == "value" {
				valueProvided = true
			}
		})
		if !valueProvided {
			return emit(stdout, stderr, jsonMode, command, nil, 1, fmt.Errorf("compare requires --value"))
		}
		raw := []byte(*value)
		if *location != "json" {
			raw, _ = json.Marshal(*value)
		}
		parsed, err := flow.ParseValue(raw)
		if err != nil {
			return emit(stdout, stderr, jsonMode, command, nil, 1, err)
		}
		apply, err := flow.SetMutation(*location, *path, parsed)
		if err != nil {
			return emit(stdout, stderr, jsonMode, command, nil, 1, err)
		}
		if *step == "" {
			return emit(stdout, stderr, jsonMode, command, nil, 1, fmt.Errorf("compare requires --step"))
		}
		mutation = flow.StepMutation{StepID: *step, Apply: apply}
	}
	runner := flow.Runner{Store: project.Store, NewClient: func(string) (*attacker.HClient, error) {
		client := attacker.NewHClient()
		client.UseBaseURL(strings.TrimRight(target.String(), "/"))
		return client, nil
	}, BeforeSend: before, AfterResponse: after, Prepare: func(request attacker.Request, _ flow.Variables) error {
		for key := range request.Headers {
			if strings.EqualFold(key, "Host") {
				delete(request.Headers, key)
			}
		}
		request.SetHeaderNonCanonical("Host", target.Host)
		return nil
	}}
	if command == "flow run" {
		result, err := runner.Run(execution, project.Flow, nil)
		code := 0
		if err != nil {
			code = 2
		}
		return emit(stdout, stderr, jsonMode, command, summary(result), code, err)
	}
	result, err := runner.Compare(execution, project.Flow, mutation)
	code := 0
	if err != nil {
		code = 2
	}
	return emit(stdout, stderr, jsonMode, command, comparisonSummary{MutationStepID: result.MutationStepID, Baseline: summary(result.Baseline), Mutated: summary(result.Mutated)}, code, err)
}

func loadScripts(ctx context.Context, project project, directory string, timeout time.Duration) (map[string]flow.BeforeSend, map[string]flow.AfterResponse, error) {
	if directory == "" {
		directory = filepath.Join(project.Root, "hooks")
	}
	before := map[string]flow.BeforeSend{}
	after := map[string]flow.AfterResponse{}
	programs := map[string]*script.Program{}
	for _, step := range project.Flow.Steps {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		for _, entry := range []struct{ name, callback string }{{step.BeforeSend, "beforeSend"}, {step.AfterResponse, "afterResponse"}} {
			if entry.name == "" {
				continue
			}
			if !safeHookName(entry.name) {
				return nil, nil, fmt.Errorf("invalid hook name %q", entry.name)
			}
			program := programs[entry.name]
			if program == nil {
				path, err := inside(directory, entry.name+".js")
				if err != nil {
					return nil, nil, fmt.Errorf("hook %q: %w", entry.name, err)
				}
				source, err := os.ReadFile(path)
				if err != nil {
					return nil, nil, err
				}
				program, err = script.Compile(path, string(source), timeout)
				if err != nil {
					return nil, nil, err
				}
				programs[entry.name] = program
			}
			if err := program.CheckContext(ctx, entry.callback); err != nil {
				return nil, nil, err
			}
			if entry.callback == "beforeSend" {
				before[entry.name] = program.BeforeSend
			} else {
				after[entry.name] = program.AfterResponse
			}
		}
	}
	return before, after, nil
}
func safeHookName(name string) bool {
	if name == "" {
		return false
	}
	for _, c := range name {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' {
			continue
		}
		return false
	}
	return true
}
