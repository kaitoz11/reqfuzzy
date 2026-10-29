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

func selectRequest(message flow.RequestSnapshot, target Target, action string) (selection, error) {
	switch target.Location {
	case "json":
		if message.BodySource == "unavailable" {
			return selection{}, fmt.Errorf("sent body is unavailable")
		}
		lookup, err := jsonutil.MutationLookupPath(target.Path)
		if err != nil {
			return selection{}, err
		}
		if err := jsonutil.ValidateUnique(message.Body); err != nil {
			return selection{}, err
		}
		if action == "remove" {
			parent, _, err := jsonutil.MutationParent(target.Path)
			if err != nil {
				return selection{}, err
			}
			container := gjson.ParseBytes(message.Body)
			if parent != "" {
				container = gjson.GetBytes(message.Body, parent)
			}
			if container.IsArray() {
				return selection{true, []byte(container.Raw)}, nil
			}
		}
		found := gjson.GetBytes(message.Body, lookup)
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

func mutationSurvived(result flow.RunResult, target Target, action string) (string, bool) {
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
		expected, err := selectRequest(*step.MutationRequest, target, action)
		if err != nil {
			return "unverified", false
		}
		actual, err := selectRequest(*step.SentRequest, target, action)
		if err != nil {
			return "unverified", false
		}
		if expected.exists != actual.exists {
			return "overwritten", false
		}
		if !expected.exists {
			if action == "remove" {
				return "verified", true
			}
			return "unverified", false
		}
		equal := bytes.Equal(expected.raw, actual.raw)
		if target.Location == "json" {
			equal, err = jsonutil.EqualJSON(actual.raw, expected.raw)
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
