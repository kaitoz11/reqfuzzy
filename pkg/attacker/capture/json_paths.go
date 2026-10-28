package capture

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type jsonLeaf struct {
	Path string
	Kind string
	Text string
}

func jsonLeaves(data []byte) []jsonLeaf {
	if !json.Valid(data) {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil
	}
	var leaves []jsonLeaf
	walkJSON(value, "", &leaves)
	return leaves
}

func walkJSON(value any, path string, leaves *[]jsonLeaf) {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			walkJSON(typed[key], joinJSONPath(path, escapeJSONPathKey(key)), leaves)
		}
	case []any:
		for index, child := range typed {
			walkJSON(child, joinJSONPath(path, fmt.Sprintf("%d", index)), leaves)
		}
	case string:
		if path != "" {
			*leaves = append(*leaves, jsonLeaf{Path: path, Kind: "string", Text: typed})
		}
	case json.Number:
		if path != "" {
			*leaves = append(*leaves, jsonLeaf{Path: path, Kind: "number", Text: typed.String()})
		}
	}
}

func joinJSONPath(parent, child string) string {
	if parent == "" {
		return child
	}
	return parent + "." + child
}

func escapeJSONPathKey(key string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `.`, `\.`, `*`, `\*`, `?`, `\?`)
	return replacer.Replace(key)
}

func eligibleCandidate(leaf jsonLeaf) bool {
	if leaf.Kind == "string" {
		return len(leaf.Text) >= 6
	}
	if leaf.Kind == "number" {
		digits := 0
		for _, character := range leaf.Text {
			if character >= '0' && character <= '9' {
				digits++
			}
		}
		return digits >= 4
	}
	return false
}
