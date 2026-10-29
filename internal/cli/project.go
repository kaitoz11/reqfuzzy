package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/capture"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
	"golang.org/x/net/http/httpguts"
	"gopkg.in/yaml.v3"
)

type manifest struct {
	Version  int               `yaml:"version"`
	Origin   string            `yaml:"origin"`
	Requests map[string]string `yaml:"requests"`
}
type project struct {
	Root     string
	Manifest manifest
	Flow     flow.Flow
	Store    *attacker.RequestStore
}

func validateTargets(project project) error {
	for _, step := range project.Flow.Steps {
		stored, err := project.Store.GetRequestContext(step.Request)
		if err != nil {
			return fmt.Errorf("step %q request %q: %w", step.ID, step.Request, err)
		}
		raw := stored.ParsedRequest.Path
		parsed, err := url.Parse(raw)
		if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.User != nil || parsed.Fragment != "" || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") {
			return fmt.Errorf("step %q: captured request target must be a relative path without a fragment", step.ID)
		}
		if !httpguts.ValidHeaderFieldName(stored.ParsedRequest.Method) {
			return fmt.Errorf("step %q: invalid request method", step.ID)
		}
	}
	return nil
}

func inside(root, relative string) (string, error) {
	if relative == "" || filepath.IsAbs(relative) {
		return "", fmt.Errorf("project paths must be relative")
	}
	clean := filepath.Clean(relative)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes project")
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	path, err := filepath.EvalSymlinks(filepath.Join(realRoot, clean))
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(realRoot, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes project through symlink")
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return "", fmt.Errorf("project path is not a regular file")
	}
	return path, nil
}

func loadProject(directory string) (project, error) {
	root, err := filepath.Abs(directory)
	if err != nil {
		return project{}, err
	}
	path, err := inside(root, "project.yaml")
	if err != nil {
		return project{}, fmt.Errorf("project manifest: %w", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return project{}, err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var m manifest
	if err := decoder.Decode(&m); err != nil {
		return project{}, fmt.Errorf("project manifest: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return project{}, fmt.Errorf("project manifest needs one YAML document")
	}
	if m.Version != 1 || len(m.Requests) == 0 {
		return project{}, fmt.Errorf("project manifest requires version 1 and named requests")
	}
	if _, err := origin(m.Origin); err != nil {
		return project{}, fmt.Errorf("invalid project origin")
	}
	path, err = inside(root, "flow.yaml")
	if err != nil {
		return project{}, fmt.Errorf("flow file: %w", err)
	}
	data, err = os.ReadFile(path)
	if err != nil {
		return project{}, err
	}
	definition, err := flow.LoadYAML(data)
	if err != nil {
		return project{}, err
	}
	store := attacker.NewRequestStore()
	for name, relative := range m.Requests {
		path, err := inside(root, relative)
		if err != nil {
			return project{}, fmt.Errorf("request %q: %w", name, err)
		}
		store.RegisterRequestFilePath(name, path)
	}
	return project{Root: root, Manifest: m, Flow: definition, Store: store}, nil
}

func origin(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return "", fmt.Errorf("origin must be an HTTP(S) scheme and host")
	}
	return parsed.Scheme + "://" + strings.ToLower(parsed.Host), nil
}

func importProject(input, directory, selected string) (any, error) {
	data, err := os.ReadFile(input)
	if err != nil {
		return nil, fmt.Errorf("read HAR: %w", err)
	}
	archive, err := capture.ParseHAR(data)
	if err != nil {
		return nil, err
	}
	origins := make(map[string]struct{})
	for _, exchange := range archive.Exchanges {
		parsed, _ := url.Parse(exchange.URL)
		value, err := origin(parsed.Scheme + "://" + parsed.Host)
		if err != nil {
			return nil, err
		}
		origins[value] = struct{}{}
	}
	if selected != "" {
		selected, err = origin(selected)
		if err != nil {
			return nil, err
		}
		if _, exists := origins[selected]; !exists {
			return nil, fmt.Errorf("selected origin has no captured requests")
		}
	} else {
		if len(origins) != 1 {
			names := make([]string, 0, len(origins))
			for name := range origins {
				names = append(names, name)
			}
			sort.Strings(names)
			return nil, fmt.Errorf("capture has multiple origins (%s); select --origin", strings.Join(names, ", "))
		}
		for name := range origins {
			selected = name
		}
	}
	filtered := capture.Capture{}
	for _, exchange := range archive.Exchanges {
		parsed, _ := url.Parse(exchange.URL)
		value, _ := origin(parsed.Scheme + "://" + parsed.Host)
		if value == selected {
			filtered.Exchanges = append(filtered.Exchanges, exchange)
		}
	}
	suggestion, err := capture.SuggestFlow(filtered)
	if err != nil {
		return nil, err
	}
	flowData, err := suggestion.YAML()
	if err != nil {
		return nil, err
	}
	root, err := filepath.Abs(directory)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(root), 0700); err != nil {
		return nil, err
	}
	// Mkdir reserves the project atomically. Existing projects are never replaced.
	if err := os.Mkdir(root, 0700); err != nil {
		return nil, fmt.Errorf("create new project directory: %w", err)
	}
	paths, err := filtered.WriteRequests(filepath.Join(root, "requests"))
	if err != nil {
		return nil, fmt.Errorf("partial project retained at %s: %w", root, err)
	}
	m := manifest{Version: 1, Origin: selected, Requests: map[string]string{}}
	for name := range paths {
		m.Requests[name] = filepath.ToSlash(filepath.Join("requests", name+".txt"))
	}
	manifestData, err := yaml.Marshal(m)
	if err != nil {
		return nil, err
	}
	links, err := json.MarshalIndent(suggestion.Links, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.Mkdir(filepath.Join(root, "hooks"), 0700); err != nil {
		return nil, err
	}
	for _, artifact := range []struct {
		name string
		data []byte
	}{{"flow.yaml", flowData}, {"links.json", links}, {"project.yaml", manifestData}} {
		f, err := os.OpenFile(filepath.Join(root, artifact.name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		_, writeErr := f.Write(artifact.data)
		closeErr := f.Close()
		if writeErr != nil {
			return nil, writeErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
	}
	return map[string]any{"project": root, "origin": selected, "requests": len(paths), "links": suggestion.Links}, nil
}
