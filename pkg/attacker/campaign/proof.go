package campaign

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/jsonutil"
	"github.com/tidwall/gjson"
)

type selection struct {
	exists bool
	raw    []byte
}

func selectRequest(message flow.RequestSnapshot, target Target) (selection, error) {
	switch target.Location {
	case "json":
		if err := jsonutil.ValidateUnique(message.Body); err != nil {
			return selection{}, err
		}
		found := gjson.GetBytes(message.Body, target.Path)
		if !found.Exists() {
			return selection{}, nil
		}
		if found.Type == gjson.JSON {
			return selection{}, fmt.Errorf("mutation target is no longer scalar")
		}
		return selection{true, []byte(found.Raw)}, nil
	case "header":
		var values []string
		for name, parts := range message.Headers {
			if strings.EqualFold(name, target.Path) {
				values = append(values, parts...)
			}
		}
		if len(values) == 0 && strings.EqualFold(target.Path, "Host") && message.Host != "" {
			values = []string{message.Host}
		}
		raw, _ := json.Marshal(values)
		return selection{len(values) > 0, raw}, nil
	case "query":
		values := message.Query[target.Path]
		raw, _ := json.Marshal(values)
		return selection{len(values) > 0, raw}, nil
	}
	return selection{}, fmt.Errorf("unsupported mutation target")
}

func mutationSurvived(result flow.RunResult, target Target) (string, bool) {
	for _, step := range result.Steps {
		if step.StepID != target.Step {
			continue
		}
		if step.MutationRequest == nil || step.SentRequest == nil {
			return "unverified", false
		}
		if target.AllowTransform {
			return "transformed", true
		}
		expected, err := selectRequest(*step.MutationRequest, target)
		if err != nil {
			return "unverified", false
		}
		actual, err := selectRequest(*step.SentRequest, target)
		if err != nil {
			return "unverified", false
		}
		if expected.exists != actual.exists {
			return "overwritten", false
		}
		if !expected.exists {
			return "verified", true
		}
		equal := bytes.Equal(expected.raw, actual.raw)
		if target.Location == "json" {
			equal, err = compare(Scalar(actual.raw), Scalar(expected.raw), "eq")
			if err != nil {
				return "unverified", false
			}
		}
		if equal {
			return "verified", true
		}
		return "overwritten", false
	}
	return "unverified", false
}
