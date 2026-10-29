package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/campaign"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/evidence"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
)

type testSummary struct {
	campaign.Result
	ArtifactsDir      string `json:"artifacts_dir"`
	RequestUpperBound int64  `json:"request_upper_bound"`
}

func runJourney(parent context.Context, command string, args []string, stdout, stderr io.Writer, jsonMode bool) int {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.BoolVar(&jsonMode, "json", jsonMode, "JSON summary")
	directory := flags.String("project", ".", "project directory")
	testFile := flags.String("test", "tests.yaml", "test definition inside project")
	base := flags.String("base-url", "", "explicit target")
	out := flags.String("out", "", "new evidence directory")
	hooks := flags.String("hooks", "", "explicit script directory")
	timeout := flags.Duration("timeout", 30*time.Second, "whole campaign deadline")
	scriptTimeout := flags.Duration("script-timeout", time.Second, "script deadline")
	maxRequests := flags.Int64("max-requests", 1000, "conservative request budget")
	delay := flags.Duration("delay", 0, "minimum delay between prepared requests")
	sensitive := flags.Bool("include-sensitive", false, "retain unredacted private HTTP evidence")
	previous := flags.String("run", "", "prior evidence directory")
	caseID := flags.String("case", "", "case to reconstruct")
	configError := func(err error) int { return emit(stdout, stderr, jsonMode, command, nil, 1, err) }
	if err := flags.Parse(args); err != nil {
		return configError(err)
	}
	if flags.NArg() != 0 || *out == "" {
		return configError(fmt.Errorf("test/replay require --out and no positional arguments"))
	}
	if *timeout <= 0 || *scriptTimeout <= 0 || *maxRequests <= 0 || *delay < 0 {
		return configError(fmt.Errorf("timeouts and max-requests must be positive; delay cannot be negative"))
	}
	target, err := parseTarget(*base)
	if err != nil {
		return configError(err)
	}
	execution, cancel := context.WithTimeout(parent, *timeout)
	defer cancel()
	var prior *evidence.Recipe
	if command == "flow replay" {
		if *previous == "" || *caseID == "" {
			return configError(fmt.Errorf("replay requires --run and --case"))
		}
		recipe, err := evidence.ReadRecipe(*previous)
		if err != nil {
			return configError(err)
		}
		allowed := false
		for _, id := range recipe.Cases {
			allowed = allowed || id == *caseID
		}
		if !allowed {
			return configError(fmt.Errorf("case is not part of the recorded plan"))
		}
		prior = &recipe
		*testFile = recipe.TestPath
	} else if *previous != "" || *caseID != "" {
		return configError(fmt.Errorf("--run and --case apply only to replay"))
	}
	discovery, err := loadJourneyProject(*directory, *testFile, *hooks)
	if err != nil {
		return configError(err)
	}
	hashes, err := evidence.Fingerprint(discovery.files)
	if err != nil {
		return configError(err)
	}
	if prior != nil {
		if err := evidence.VerifyInputs(prior.Inputs, hashes); err != nil {
			return configError(err)
		}
	}
	// Reload inside the fingerprint window; executable definitions must match the plan.
	loaded, err := loadJourneyProject(*directory, *testFile, *hooks)
	if err != nil {
		return configError(err)
	}
	reloaded, err := evidence.Fingerprint(loaded.files)
	if err != nil {
		return configError(err)
	}
	if err := evidence.VerifyInputs(hashes, reloaded); err != nil {
		return configError(err)
	}
	if prior != nil {
		loaded.spec, err = selectedCase(loaded.spec, *caseID)
		if err != nil {
			return configError(err)
		}
	}
	if err := validateTargets(loaded.project, loaded.additional()...); err != nil {
		return configError(err)
	}
	before, after, err := loadScripts(execution, loaded.project, *hooks, *scriptTimeout, loaded.additional()...)
	if err != nil {
		if execution.Err() != nil {
			return emit(stdout, stderr, jsonMode, command, nil, 2, execution.Err())
		}
		return configError(err)
	}
	runner := newRunner(loaded.project, target, before, after, *delay)
	if err := campaign.Preflight(runner, loaded.project.Flow, loaded.verification, loaded.spec); err != nil {
		return configError(err)
	}
	steps := len(loaded.project.Flow.Steps)
	if loaded.verification != nil {
		steps += len(loaded.verification.Steps)
	}
	upperBound := int64(len(loaded.spec.Cases)+1) * int64(steps)
	if upperBound > *maxRequests {
		return configError(fmt.Errorf("planned request upper bound %d exceeds --max-requests %d", upperBound, *maxRequests))
	}
	current, err := evidence.Fingerprint(loaded.files)
	if err != nil {
		return configError(err)
	}
	if err := evidence.VerifyInputs(hashes, current); err != nil {
		return configError(err)
	}
	ids := make([]string, 0, len(loaded.spec.Cases))
	for _, candidate := range loaded.spec.Cases {
		ids = append(ids, candidate.ID)
	}
	store, err := evidence.NewStore(*out, evidence.Recipe{FormatVersion: 1, TestPath: relativeTestPath(*testFile), Inputs: hashes, Cases: ids, BaseURL: target.String()}, loaded.spec.Redact, *sensitive)
	if err != nil {
		return configError(err)
	}
	result, runErr := campaign.Run(execution, runner, loaded.project.Flow, loaded.verification, loaded.spec, campaign.Options{Record: store.Record})
	afterHashes, hashErr := evidence.Fingerprint(loaded.files)
	if hashErr == nil {
		hashErr = evidence.VerifyInputs(hashes, afterHashes)
	}
	if hashErr != nil {
		runErr = fmt.Errorf("project inputs changed or became unavailable during the run")
	}
	if runErr != nil {
		result.Outcome = campaign.Inconclusive
	}
	if err := store.Finish(result, runErr); err != nil {
		return emit(stdout, stderr, jsonMode, command, testSummary{result, store.Directory(), upperBound}, 2, fmt.Errorf("could not finalize evidence; partial files retained"))
	}
	code := 0
	if result.Outcome == campaign.Fail {
		code = 3
	} else if result.Outcome == campaign.Inconclusive || runErr != nil {
		code = 2
	}
	return emit(stdout, stderr, jsonMode, command, testSummary{result, store.Directory(), upperBound}, code, runErr)
}

func parseTarget(raw string) (*url.URL, error) {
	target, err := url.Parse(raw)
	if err != nil || target.Host == "" || (target.Scheme != "http" && target.Scheme != "https") || target.User != nil || target.RawQuery != "" || target.ForceQuery || target.Fragment != "" {
		return nil, fmt.Errorf("an explicit HTTP(S) --base-url without credentials, query, or fragment is required")
	}
	return target, nil
}

func newRunner(project project, target *url.URL, before map[string]flow.BeforeSend, after map[string]flow.AfterResponse, delay time.Duration) flow.Runner {
	var last time.Time
	return flow.Runner{Store: project.Store, NewClient: func(string) (*attacker.HClient, error) {
		client := attacker.NewHClient()
		client.UseBaseURL(strings.TrimRight(target.String(), "/"))
		return client, nil
	}, BeforeSend: before, AfterResponse: after, Initialize: func(request attacker.Request, _ flow.Variables) error {
		for key := range request.Headers {
			if strings.EqualFold(key, "Host") {
				delete(request.Headers, key)
			}
		}
		request.SetHeaderNonCanonical("Host", target.Host)
		return nil
	}, Prepare: func(request attacker.Request, _ flow.Variables) error {
		if !last.IsZero() && delay > 0 {
			remaining := delay - time.Since(last)
			if remaining > 0 {
				timer := time.NewTimer(remaining)
				defer timer.Stop()
				select {
				case <-request.Context().Done():
					return request.Context().Err()
				case <-timer.C:
				}
			}
		}
		last = time.Now()
		return nil
	}}
}
