// Package evidence writes private, versioned journey-test artifacts and replay recipes.
package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker/campaign"
)

type Recipe struct {
	FormatVersion int               `json:"format_version"`
	TestPath      string            `json:"test_path"`
	Inputs        map[string]string `json:"inputs"`
	Cases         []string          `json:"cases"`
	BaseURL       string            `json:"base_url"`
	GoVersion     string            `json:"go_version"`
	ToolVersion   string            `json:"tool_version"`
	Revision      string            `json:"revision,omitempty"`
	Modified      bool              `json:"modified,omitempty"`
}
type Store struct {
	directory string
	recipe    Recipe
	redaction campaign.Redaction
	sensitive bool
}

func validateRecipe(recipe Recipe) error {
	clean := filepath.Clean(recipe.TestPath)
	if recipe.FormatVersion != 1 || recipe.TestPath == "" || filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return fmt.Errorf("invalid version or contained test path in recipe")
	}
	if len(recipe.Inputs) == 0 || len(recipe.Cases) == 0 {
		return fmt.Errorf("recipe needs input hashes and cases")
	}
	for _, hash := range recipe.Inputs {
		bytes, err := hex.DecodeString(hash)
		if err != nil || len(bytes) != 32 {
			return fmt.Errorf("recipe needs SHA-256 input hashes")
		}
	}
	seen := map[string]bool{}
	for _, id := range recipe.Cases {
		if !campaign.SafeID(id) || id == "baseline" || seen[id] {
			return fmt.Errorf("invalid or duplicate case in recipe")
		}
		seen[id] = true
	}
	target, err := url.Parse(recipe.BaseURL)
	if err != nil || target.Host == "" || (target.Scheme != "http" && target.Scheme != "https") || target.User != nil || target.RawQuery != "" || target.Fragment != "" {
		return fmt.Errorf("invalid recipe base URL")
	}
	return nil
}

func NewStore(directory string, recipe Recipe, redaction campaign.Redaction, includeSensitive bool) (*Store, error) {
	if err := validateRecipe(recipe); err != nil {
		return nil, err
	}
	root, err := filepath.Abs(directory)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(root), 0700); err != nil {
		return nil, err
	}
	if err := os.Mkdir(root, 0700); err != nil {
		return nil, fmt.Errorf("create new evidence directory: %w", err)
	}
	recipe.GoVersion = runtime.Version()
	recipe.ToolVersion = "(devel)"
	if info, ok := debug.ReadBuildInfo(); ok {
		recipe.ToolVersion = info.Main.Version
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" {
				recipe.Revision = setting.Value
			}
			if setting.Key == "vcs.modified" {
				recipe.Modified = setting.Value == "true"
			}
		}
	}
	store := &Store{directory: root, recipe: recipe, redaction: redaction, sensitive: includeSensitive}
	if err := store.write("plan.json", recipe); err != nil {
		return nil, err
	}
	return store, nil
}
func (s *Store) Directory() string { return s.directory }
func (s *Store) write(name string, value any) error {
	file, err := os.OpenFile(filepath.Join(s.directory, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	writeErr := encoder.Encode(value)
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}
func (s *Store) Record(trial campaign.Trial) error {
	allowed := trial.ID == "baseline"
	for _, id := range s.recipe.Cases {
		allowed = allowed || id == trial.ID
	}
	if !allowed || !campaign.SafeID(trial.ID) {
		return fmt.Errorf("trial is not part of the recorded plan")
	}
	return s.write(trial.ID+".json", struct {
		FormatVersion int            `json:"format_version"`
		Trial         campaign.Trial `json:"trial"`
		Flow          runEvidence    `json:"flow"`
		Verification  runEvidence    `json:"verification"`
	}{1, trial, s.run(trial.Flow), s.run(trial.Verification)})
}
func (s *Store) Finish(result campaign.Result, runErr error) error {
	reason := ""
	if runErr != nil {
		reason = "execution interrupted before completion"
		if errors.Is(runErr, context.Canceled) {
			reason = "execution canceled"
		} else if errors.Is(runErr, context.DeadlineExceeded) {
			reason = "execution deadline exceeded"
		}
	}
	return s.write("result.json", struct {
		FormatVersion int             `json:"format_version"`
		Result        campaign.Result `json:"result"`
		Error         string          `json:"error,omitempty"`
	}{1, result, reason})
}

func ReadRecipe(directory string) (Recipe, error) {
	file, err := os.Open(filepath.Join(directory, "plan.json"))
	if err != nil {
		return Recipe{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 2<<20))
	decoder.DisallowUnknownFields()
	var recipe Recipe
	if err := decoder.Decode(&recipe); err != nil {
		return Recipe{}, fmt.Errorf("read evidence recipe: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Recipe{}, fmt.Errorf("recipe needs one JSON document")
	}
	if err := validateRecipe(recipe); err != nil {
		return Recipe{}, err
	}
	return recipe, nil
}

func Fingerprint(files map[string]string) (map[string]string, error) {
	result := make(map[string]string, len(files))
	for key, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("fingerprint input %q: %w", key, err)
		}
		digest := sha256.Sum256(data)
		result[key] = hex.EncodeToString(digest[:])
	}
	return result, nil
}
func VerifyInputs(expected, current map[string]string) error {
	if len(expected) != len(current) {
		return fmt.Errorf("input set changed since the recorded run")
	}
	for key, hash := range expected {
		if current[key] != hash {
			return fmt.Errorf("input fingerprint changed: %s", key)
		}
	}
	return nil
}
