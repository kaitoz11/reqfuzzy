package flow

import (
	"fmt"
	"net/http"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker/rawreq"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/urlform"
)

// PreflightTarget validates a selected request's static location structure
// without creating clients. Values and field existence are checked after flow
// bindings, because a binding may create a field absent from the capture.
func (r Runner) PreflightTarget(definition Flow, stepID, location, path string) error {
	if r.Store == nil {
		return fmt.Errorf("request store is required")
	}
	for _, step := range definition.Steps {
		if step.ID != stepID {
			continue
		}
		stored, err := r.Store.GetRequestContext(step.Request)
		if err != nil {
			return &StepError{Kind: RequestError, StepID: step.ID, Err: err}
		}
		if err := validateTarget(stored.ParsedRequest, location, path); err != nil {
			return &StepError{Kind: MutationError, StepID: step.ID, Err: err}
		}
		return nil
	}
	return fmt.Errorf("mutation step does not exist")
}

func validateTarget(parsed *rawreq.ParsedRawRequest, location, path string) error {
	switch location {
	case "path":
		_, _, _, err := pathAddress(parsed.Path, path)
		return err
	case "form":
		headers := make(http.Header)
		for _, header := range parsed.Headers {
			headers.Add(header.Key, header.Value)
		}
		_, err := urlform.Parse(headers, parsed.Body)
		return err
	case "header", "query", "json":
		return nil
	default:
		return fmt.Errorf("unsupported target location")
	}
}
