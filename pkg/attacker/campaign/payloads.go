package campaign

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/big"
	"path/filepath"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

const MaxExpandedCases = 10000
const MaxPayloadBytes = 8 << 20
const MaxExpandedBytes = 64 << 20

type PayloadResolver func(string) ([]byte, error)
type IntegerRange struct {
	From Scalar `yaml:"from"`
	To   Scalar `yaml:"to"`
	Step Scalar `yaml:"step,omitempty"`
}

func (interval *IntegerRange) UnmarshalYAML(node *yaml.Node) error {
	if err := recordFields(node, "from", "to", "step"); err != nil {
		return err
	}
	type plain IntegerRange
	var decoded plain
	if err := node.Decode(&decoded); err != nil {
		return err
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i+1].Tag != "!!null" {
			continue
		}
		switch node.Content[i].Value {
		case "from":
			decoded.From = Scalar("null")
		case "to":
			decoded.To = Scalar("null")
		case "step":
			decoded.Step = Scalar("null")
		}
	}
	*interval = IntegerRange(decoded)
	return nil
}

type PayloadDefinition struct {
	Action string        `yaml:"action"`
	Values []Scalar      `yaml:"values,omitempty"`
	File   string        `yaml:"file,omitempty"`
	Format string        `yaml:"format,omitempty"`
	Range  *IntegerRange `yaml:"range,omitempty"`
	Unique bool          `yaml:"unique,omitempty"`
	Render string        `yaml:"render,omitempty"`
	Encode []string      `yaml:"encode,omitempty"`
}
type PayloadSource struct {
	ID                string `yaml:"id"`
	Use               string `yaml:"use,omitempty"`
	PayloadDefinition `yaml:",inline"`
}
type payloadLibrary struct {
	Version           int `yaml:"version"`
	PayloadDefinition `yaml:",inline"`
}

var payloadFields = []string{"action", "values", "file", "format", "range", "unique", "render", "encode"}

func (source *PayloadSource) UnmarshalYAML(node *yaml.Node) error {
	if err := recordFields(node, append([]string{"id", "use"}, payloadFields...)...); err != nil {
		return err
	}
	if err := validateEncodeSyntax(node); err != nil {
		return err
	}
	type plain PayloadSource
	var decoded plain
	if err := node.Decode(&decoded); err != nil {
		return err
	}
	restorePayloadNulls(node, &decoded.PayloadDefinition)
	*source = PayloadSource(decoded)
	return nil
}

func (library *payloadLibrary) UnmarshalYAML(node *yaml.Node) error {
	if err := recordFields(node, append([]string{"version"}, payloadFields...)...); err != nil {
		return err
	}
	if err := validateEncodeSyntax(node); err != nil {
		return err
	}
	type plain payloadLibrary
	var decoded plain
	if err := node.Decode(&decoded); err != nil {
		return err
	}
	restorePayloadNulls(node, &decoded.PayloadDefinition)
	*library = payloadLibrary(decoded)
	return nil
}

func restorePayloadNulls(node *yaml.Node, definition *PayloadDefinition) {
	unwrap := func(n *yaml.Node) *yaml.Node {
		for i := 0; i < 32 && n.Kind == yaml.AliasNode && n.Alias != nil; i++ {
			n = n.Alias
		}
		return n
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		value := unwrap(node.Content[i+1])
		if node.Content[i].Value == "values" && value.Kind == yaml.SequenceNode {
			for index, entry := range value.Content {
				if index < len(definition.Values) && unwrap(entry).Tag == "!!null" {
					definition.Values[index] = Scalar("null")
				}
			}
		}
		if node.Content[i].Value == "range" && definition.Range != nil {
			for j := 0; j+1 < len(value.Content); j += 2 {
				if unwrap(value.Content[j+1]).Tag != "!!null" {
					continue
				}
				switch value.Content[j].Value {
				case "from":
					definition.Range.From = Scalar("null")
				case "to":
					definition.Range.To = Scalar("null")
				case "step":
					definition.Range.Step = Scalar("null")
				}
			}
		}
	}
}

func decodePayload(data []byte, out any) error {
	if len(data) > MaxPayloadBytes || !utf8.Valid(data) {
		return fmt.Errorf("payload file exceeds size limit or is not UTF-8")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(out); err != nil {
		return fmt.Errorf("invalid payload definition: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("payload definition needs one YAML document")
	}
	return nil
}

func ResolvePayloads(spec Spec, resolve PayloadResolver) (Spec, error) {
	result := spec
	result.Cases = append([]Case(nil), spec.Cases...)
	result.Payloads = nil
	totalBytes := 0
	account := func(candidate Case) error {
		size := len(candidate.Value) + len(candidate.Render)
		if size > MaxExpandedBytes-totalBytes {
			return fmt.Errorf("expanded payload definitions exceed size limit")
		}
		totalBytes += size
		return nil
	}
	for _, candidate := range result.Cases {
		if err := account(candidate); err != nil {
			return Spec{}, err
		}
	}
	if len(result.Cases) > MaxExpandedCases {
		return Spec{}, fmt.Errorf("campaign exceeds maximum case count")
	}
	read := func(path string) ([]byte, error) {
		if resolve == nil {
			return nil, fmt.Errorf("external payloads require an explicit resolver")
		}
		data, err := resolve(path)
		if err != nil {
			return nil, err
		}
		if len(data) > MaxPayloadBytes || !utf8.Valid(data) {
			return nil, fmt.Errorf("payload file exceeds size limit or is not UTF-8")
		}
		return data, nil
	}
	seenSources := map[string]bool{}
	for _, source := range spec.Payloads {
		if !SafeID(source.ID) || len(source.ID) > 56 || seenSources[source.ID] {
			return Spec{}, fmt.Errorf("payload namespaces must be unique safe IDs up to 56 characters")
		}
		seenSources[source.ID] = true
		definition := source.PayloadDefinition
		base := ""
		if source.Use != "" {
			if definition.Action != "" || definition.Values != nil || definition.File != "" || definition.Format != "" || definition.Range != nil || definition.Unique || definition.Render != "" || len(definition.Encode) > 0 {
				return Spec{}, fmt.Errorf("payload use cannot override library fields")
			}
			data, err := read(source.Use)
			if err != nil {
				return Spec{}, fmt.Errorf("payload %q: %w", source.ID, err)
			}
			var library payloadLibrary
			if err := decodePayload(data, &library); err != nil {
				return Spec{}, err
			}
			if library.Version != 1 {
				return Spec{}, fmt.Errorf("payload library requires version 1")
			}
			definition = library.PayloadDefinition
			base = filepath.Dir(source.Use)
		}
		if len(definition.Encode) > 16 {
			return Spec{}, fmt.Errorf("payload encoding pipeline exceeds 16 stages")
		}
		values, err := payloadValues(definition, base, read)
		if err != nil {
			return Spec{}, fmt.Errorf("payload %q: %w", source.ID, err)
		}
		duplicates := map[string]bool{}
		for index, value := range values {
			if definition.Unique && duplicates[string(value)] {
				continue
			}
			duplicates[string(value)] = true
			if len(result.Cases) >= MaxExpandedCases {
				return Spec{}, fmt.Errorf("campaign exceeds maximum case count")
			}
			candidate := Case{ID: fmt.Sprintf("%s-%06d", source.ID, index+1), Action: definition.Action, Value: value, Render: definition.Render, Encode: definition.Encode, Source: source.ID, SourceIndex: index + 1}
			if err := account(candidate); err != nil {
				return Spec{}, err
			}
			result.Cases = append(result.Cases, candidate)
		}
	}
	return result, nil
}

func payloadValues(def PayloadDefinition, base string, read PayloadResolver) ([]Scalar, error) {
	if def.Action == "remove" {
		if def.Values != nil || def.File != "" || def.Range != nil || def.Format != "" || def.Render != "" || len(def.Encode) > 0 || def.Unique {
			return nil, fmt.Errorf("remove payload takes no values or transformations")
		}
		return []Scalar{nil}, nil
	}
	sources := 0
	if def.Values != nil {
		sources++
	}
	if def.File != "" {
		sources++
	}
	if def.Range != nil {
		sources++
	}
	if sources != 1 || def.Action == "" {
		return nil, fmt.Errorf("payload needs an action and exactly one values, file or range source")
	}
	if def.File == "" && def.Format != "" {
		return nil, fmt.Errorf("format requires a payload file")
	}
	if def.Values != nil {
		if len(def.Values) == 0 || len(def.Values) > MaxExpandedCases {
			return nil, fmt.Errorf("payload values count is outside supported bounds")
		}
		for _, value := range def.Values {
			if _, err := scalar(value); err != nil {
				return nil, err
			}
		}
		return def.Values, nil
	}
	if def.Range != nil {
		return rangeValues(*def.Range)
	}
	if filepath.IsAbs(def.File) || filepath.VolumeName(def.File) != "" {
		return nil, fmt.Errorf("payload file paths must be relative")
	}
	data, err := read(filepath.Join(base, def.File))
	if err != nil {
		return nil, err
	}
	if def.Format != "" && def.Format != "lines" && def.Format != "jsonl" {
		return nil, fmt.Errorf("payload file format must be lines or jsonl")
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), MaxPayloadBytes+1)
	var values []Scalar
	for scanner.Scan() {
		if len(values) >= MaxExpandedCases {
			return nil, fmt.Errorf("payload file has too many entries")
		}
		var value Scalar
		if def.Format == "jsonl" {
			var err error
			value, err = scalar(scanner.Bytes())
			if err != nil {
				return nil, fmt.Errorf("invalid JSON scalar at payload line %d", len(values)+1)
			}
		} else {
			encoded, err := stringScalar(scanner.Text())
			if err != nil {
				return nil, err
			}
			value = encoded
		}
		values = append(values, value)
	}
	if scanner.Err() != nil {
		return nil, fmt.Errorf("could not scan payload file")
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("payload file is empty")
	}
	return values, nil
}

func rangeValues(spec IntegerRange) ([]Scalar, error) {
	integer := func(raw Scalar) (*big.Int, error) {
		if len(raw) == 0 || len(raw) > 4096 {
			return nil, fmt.Errorf("range needs supported integers")
		}
		value, ok := new(big.Int).SetString(string(raw), 10)
		if !ok {
			return nil, fmt.Errorf("range needs decimal integers")
		}
		return value, nil
	}
	from, err := integer(spec.From)
	if err != nil {
		return nil, err
	}
	to, err := integer(spec.To)
	if err != nil {
		return nil, err
	}
	step := big.NewInt(1)
	if len(spec.Step) > 0 {
		step, err = integer(spec.Step)
		if err != nil {
			return nil, err
		}
	}
	delta := new(big.Int).Sub(to, from)
	if step.Sign() == 0 || (delta.Sign() != 0 && delta.Sign() != step.Sign()) {
		return nil, fmt.Errorf("range step is zero or has the wrong direction")
	}
	count := new(big.Int).Quo(new(big.Int).Abs(delta), new(big.Int).Abs(step))
	count.Add(count, big.NewInt(1))
	if count.Cmp(big.NewInt(MaxExpandedCases)) > 0 {
		return nil, fmt.Errorf("payload range has too many entries")
	}
	values := make([]Scalar, 0, int(count.Int64()))
	current := new(big.Int).Set(from)
	for index := int64(0); index < count.Int64(); index++ {
		values = append(values, Scalar(current.String()))
		current.Add(current, step)
	}
	return values, nil
}
