package cli

import (
	"bytes"
	_ "embed"
	"flag"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
	"gopkg.in/yaml.v3"
)

//go:embed flow_map.html
var flowMapHTML string

//go:embed flow_map_core.js
var flowMapCore string

//go:embed flow_map_ui.js
var flowMapUI string

type mapFlow struct {
	Key        string         `json:"key"`
	File       string         `json:"file"`
	Label      string         `json:"label"`
	Definition map[string]any `json:"definition"`
}
type mapTarget struct {
	Step     string `json:"step"`
	Location string `json:"location"`
	Path     string `json:"path"`
}
type mapCheck struct {
	ID       string `json:"id"`
	Phase    string `json:"phase"`
	Step     string `json:"step"`
	Variable string `json:"variable,omitempty"`
}
type mapCampaign struct {
	Name   string     `json:"name"`
	Target mapTarget  `json:"target"`
	Checks []mapCheck `json:"checks"`
}
type mapProject struct {
	FormatVersion int          `json:"format_version"`
	Requests      []string     `json:"requests"`
	Flows         []mapFlow    `json:"flows"`
	Campaign      *mapCampaign `json:"campaign,omitempty"`
}
type mapSummary struct {
	File         string `json:"file"`
	Steps        int    `json:"steps"`
	Dependencies int    `json:"dependencies"`
}

func runFlowMap(args []string, stdout, stderr io.Writer, jsonMode bool) int {
	flags := flag.NewFlagSet("flow map", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.BoolVar(&jsonMode, "json", jsonMode, "JSON summary")
	directory := flags.String("project", ".", "project directory")
	out := flags.String("out", "", "new offline HTML map")
	testFile := flags.String("test", "", "optional campaign definition inside project")
	fail := func(err error) int { return emit(stdout, stderr, jsonMode, "flow map", nil, 1, err) }
	if err := flags.Parse(args); err != nil {
		return fail(err)
	}
	if flags.NArg() != 0 || *out == "" {
		return fail(fmt.Errorf("flow map requires --out FILE and no positional arguments"))
	}
	p, err := loadProject(*directory)
	if err != nil {
		return fail(err)
	}
	definitions := []flow.Flow{p.Flow}
	files := []string{"flow.yaml"}
	labels := []string{"Journey"}
	keys := []string{"flow"}
	document := mapProject{FormatVersion: 1, Requests: []string{}, Flows: []mapFlow{}}
	if *testFile != "" {
		journey, err := loadJourneyProject(*directory, *testFile, "")
		if err != nil {
			return fail(err)
		}
		p = journey.project
		definitions[0] = p.Flow
		spec := journey.spec
		document.Campaign = &mapCampaign{Name: spec.Name, Target: mapTarget{spec.Target.Step, spec.Target.Location, spec.Target.Path}, Checks: []mapCheck{}}
		for _, check := range spec.Checks {
			document.Campaign.Checks = append(document.Campaign.Checks, mapCheck{check.ID, check.Phase, check.Step, check.Variable})
		}
		if journey.verification != nil {
			definitions = append(definitions, *journey.verification)
			files = append(files, spec.Verify)
			labels = append(labels, "Verification")
			keys = append(keys, "verify")
		}
	}
	for name := range p.Manifest.Requests {
		document.Requests = append(document.Requests, name)
	}
	sort.Strings(document.Requests)
	summary := mapSummary{}
	for i, definition := range definitions {
		encoded, err := yaml.Marshal(definition)
		if err != nil {
			return fail(err)
		}
		var fields map[string]any
		if err := yaml.Unmarshal(encoded, &fields); err != nil {
			return fail(err)
		}
		document.Flows = append(document.Flows, mapFlow{keys[i], files[i], labels[i], fields})
		summary.Steps += len(definition.Steps)
		for _, step := range definition.Steps {
			summary.Dependencies += len(step.Bind)
		}
	}
	// Only owned, embedded program text is marked as JS. Project data is left
	// structured so html/template JSON-escapes it, including closing script text.
	page, err := template.New("flow-map").Parse(flowMapHTML)
	if err != nil {
		return fail(err)
	}
	var buffer bytes.Buffer
	if err := page.Execute(&buffer, struct {
		Project  mapProject
		Core, UI template.JS
	}{document, template.JS(flowMapCore), template.JS(flowMapUI)}); err != nil {
		return fail(err)
	}
	path, err := filepath.Abs(*out)
	if err != nil {
		return fail(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fail(err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fail(fmt.Errorf("create new map: %w", err))
	}
	_, writeErr := file.Write(buffer.Bytes())
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		os.Remove(path)
		if writeErr != nil {
			return fail(writeErr)
		}
		return fail(closeErr)
	}
	summary.File = path
	return emit(stdout, stderr, jsonMode, "flow map", summary, 0, nil)
}
