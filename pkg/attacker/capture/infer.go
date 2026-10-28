package capture

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/rawreq"
	"gopkg.in/yaml.v3"
)

type Link struct {
	FromStep     string
	FromJSONPath string
	ToStep       string
	ToLocation   string
	ToPath       string
	Prefix       string
	Confidence   string
}

type Suggestion struct {
	Flow  flow.Flow
	Links []Link
}

type sourceValue struct {
	StepIndex int
	Leaf      jsonLeaf
}

type requestValue struct {
	Location string
	Path     string
	Prefix   string
	Kind     string
	Text     string
}

func SuggestFlow(c Capture) (Suggestion, error) {
	if len(c.Exchanges) == 0 {
		return Suggestion{}, fmt.Errorf("capture has no exchanges")
	}
	suggestion := Suggestion{Flow: flow.Flow{Name: "har-suggestion", Steps: make([]flow.Step, len(c.Exchanges))}}
	for index, exchange := range c.Exchanges {
		step := flow.Step{ID: exchange.Name, Request: exchange.Name}
		if exchange.ResponseStatus >= 100 && exchange.ResponseStatus <= 599 {
			status := exchange.ResponseStatus
			step.ExpectStatus = &status
		}
		suggestion.Flow.Steps[index] = step
	}
	if err := flow.Validate(suggestion.Flow); err != nil {
		return Suggestion{}, fmt.Errorf("invalid capture request names: %w", err)
	}

	sources := make(map[string][]sourceValue)
	variables := make(map[string]string)
	usedNames := make(map[string]struct{})
	for targetIndex, exchange := range c.Exchanges {
		if targetIndex > 0 {
			values, err := requestValues(exchange)
			if err != nil {
				return Suggestion{}, fmt.Errorf("capture exchange %q: %w", exchange.Name, err)
			}
			for _, destination := range values {
				candidates := sources[destination.Text]
				if destination.Kind != "" || destination.Prefix != "" {
					matching := make([]sourceValue, 0, len(candidates))
					for _, candidate := range candidates {
						if destination.Kind != "" && candidate.Leaf.Kind != destination.Kind {
							continue
						}
						if destination.Prefix != "" && candidate.Leaf.Kind != "string" {
							continue
						}
						matching = append(matching, candidate)
					}
					candidates = matching
				}
				if len(candidates) != 1 {
					continue
				}
				source := candidates[0]
				key := fmt.Sprintf("%d:%s", source.StepIndex, source.Leaf.Path)
				variable := variables[key]
				if variable == "" {
					variable = variableName(source.StepIndex, source.Leaf.Path, usedNames)
					variables[key] = variable
					suggestion.Flow.Steps[source.StepIndex].Extract = append(suggestion.Flow.Steps[source.StepIndex].Extract, flow.Extraction{Name: variable, JSONPath: source.Leaf.Path})
				}
				suggestion.Flow.Steps[targetIndex].Bind = append(suggestion.Flow.Steps[targetIndex].Bind, flow.Binding{Location: destination.Location, Path: destination.Path, Variable: variable, Prefix: destination.Prefix})
				confidence := "medium"
				if source.Leaf.Kind == "string" && len(source.Leaf.Text) >= 8 {
					confidence = "high"
				}
				suggestion.Links = append(suggestion.Links, Link{
					FromStep: c.Exchanges[source.StepIndex].Name, FromJSONPath: source.Leaf.Path,
					ToStep: exchange.Name, ToLocation: destination.Location, ToPath: destination.Path,
					Prefix: destination.Prefix, Confidence: confidence,
				})
			}
		}
		if exchange.ResponseBodyPresent {
			for _, leaf := range jsonLeaves(exchange.ResponseBody) {
				if eligibleCandidate(leaf) {
					sources[leaf.Text] = append(sources[leaf.Text], sourceValue{StepIndex: targetIndex, Leaf: leaf})
				}
			}
		}
	}
	if err := flow.Validate(suggestion.Flow); err != nil {
		return Suggestion{}, fmt.Errorf("invalid suggested flow: %w", err)
	}
	return suggestion, nil
}

func (s Suggestion) YAML() ([]byte, error) {
	if err := flow.Validate(s.Flow); err != nil {
		return nil, err
	}
	return yaml.Marshal(s.Flow)
}

func requestValues(exchange Exchange) ([]requestValue, error) {
	parsed, err := rawreq.ParseRawRequest(exchange.RequestRaw)
	if err != nil {
		return nil, fmt.Errorf("parse raw request: %w", err)
	}
	requestURL, err := url.Parse(exchange.URL)
	if err != nil {
		return nil, fmt.Errorf("parse request URL: %w", err)
	}
	var values []requestValue
	query := requestURL.Query()
	keys := make([]string, 0, len(query))
	for key := range query {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if len(query[key]) != 1 {
			continue
		}
		for _, value := range query[key] {
			values = append(values, requestValue{Location: "query", Path: key, Text: value})
		}
	}
	headerCounts := make(map[string]int, len(parsed.Headers))
	for _, header := range parsed.Headers {
		headerCounts[strings.ToLower(header.Key)]++
	}
	for _, header := range parsed.Headers {
		if ignoredHeader(header.Key) || headerCounts[strings.ToLower(header.Key)] != 1 {
			continue
		}
		if strings.EqualFold(header.Key, "Authorization") && len(header.Value) >= len("Bearer ") && strings.EqualFold(header.Value[:len("Bearer ")], "Bearer ") {
			values = append(values, requestValue{Location: "header", Path: header.Key, Prefix: header.Value[:len("Bearer ")], Text: header.Value[len("Bearer "):]})
			continue
		}
		values = append(values, requestValue{Location: "header", Path: header.Key, Text: header.Value})
	}
	for _, leaf := range jsonLeaves(parsed.Body) {
		values = append(values, requestValue{Location: "json", Path: leaf.Path, Kind: leaf.Kind, Text: leaf.Text})
	}
	return values, nil
}

func ignoredHeader(name string) bool {
	switch strings.ToLower(name) {
	case "host", "cookie", "content-length", "transfer-encoding", "connection", "accept-encoding":
		return true
	}
	return false
}

func variableName(stepIndex int, path string, used map[string]struct{}) string {
	base := fmt.Sprintf("v_%04d_%s", stepIndex+1, pathSlug(path))
	name := base
	for suffix := 2; ; suffix++ {
		if _, exists := used[name]; !exists {
			used[name] = struct{}{}
			return name
		}
		name = fmt.Sprintf("%s_%d", base, suffix)
	}
}
