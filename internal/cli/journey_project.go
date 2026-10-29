package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker/campaign"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
)

type journeyProject struct {
	project      project
	spec         campaign.Spec
	verification *flow.Flow
	files        map[string]string
}

func (j journeyProject) additional() []flow.Flow {
	if j.verification == nil {
		return nil
	}
	return []flow.Flow{*j.verification}
}

func loadJourneyProject(directory, testFile, hooks string) (journeyProject, error) {
	p, err := loadProject(directory)
	if err != nil {
		return journeyProject{}, err
	}
	testPath, err := inside(p.Root, testFile)
	if err != nil {
		return journeyProject{}, fmt.Errorf("test file: %w", err)
	}
	data, err := os.ReadFile(testPath)
	if err != nil {
		return journeyProject{}, err
	}
	spec, err := campaign.LoadYAML(data)
	if err != nil {
		return journeyProject{}, err
	}
	loaded := journeyProject{project: p, spec: spec, files: map[string]string{"test": testPath}}
	if spec.Verify != "" {
		path, err := inside(p.Root, spec.Verify)
		if err != nil {
			return journeyProject{}, fmt.Errorf("verification file: %w", err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return journeyProject{}, err
		}
		verification, err := flow.LoadYAMLWithVariables(data, campaign.DeclaredVariables(p.Flow, nil))
		if err != nil {
			return journeyProject{}, fmt.Errorf("verification flow: %w", err)
		}
		loaded.verification = &verification
		loaded.files["verification"] = path
	}
	for key, relative := range map[string]string{"project": "project.yaml", "flow": "flow.yaml"} {
		path, err := inside(p.Root, relative)
		if err != nil {
			return journeyProject{}, err
		}
		loaded.files[key] = path
	}
	for name, relative := range p.Manifest.Requests {
		path, err := inside(p.Root, relative)
		if err != nil {
			return journeyProject{}, err
		}
		loaded.files["request:"+name] = path
	}
	definitions := append([]flow.Flow{p.Flow}, loaded.additional()...)
	for _, definition := range definitions {
		for _, step := range definition.Steps {
			for _, name := range []string{step.BeforeSend, step.AfterResponse} {
				if name == "" {
					continue
				}
				path, err := scriptPath(p, hooks, name)
				if err != nil {
					return journeyProject{}, fmt.Errorf("hook %q: %w", name, err)
				}
				loaded.files["hook:"+name] = path
			}
		}
	}
	return loaded, nil
}

func selectedCase(spec campaign.Spec, id string) (campaign.Spec, error) {
	for _, candidate := range spec.Cases {
		if candidate.ID == id {
			spec.Cases = []campaign.Case{candidate}
			return spec, nil
		}
	}
	return campaign.Spec{}, fmt.Errorf("case is not part of the test definition")
}
func relativeTestPath(path string) string { return filepath.ToSlash(filepath.Clean(path)) }
