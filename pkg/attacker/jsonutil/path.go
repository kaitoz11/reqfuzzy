package jsonutil

import (
	"fmt"
	"strings"

	"github.com/tidwall/gjson"
)

// MutationLookupPath resolves a literal SJSON mutation path to its GJSON lookup.
// SJSON's leading ':' forces an object key and is not part of that key.
// Selectors, modifiers, wildcard queries, and append indices are not field addresses.
func MutationLookupPath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("JSON mutation path is empty")
	}
	var parts []string
	var part strings.Builder
	start := true
	forced := false
	finish := func() error {
		if part.Len() == 0 {
			return fmt.Errorf("JSON mutation path has an empty field")
		}
		value := part.String()
		if value == "-1" && !forced {
			return fmt.Errorf("JSON append indices require an explicit array action")
		}
		parts = append(parts, gjson.Escape(value))
		part.Reset()
		start = true
		forced = false
		return nil
	}
	for index := 0; index < len(path); index++ {
		character := path[index]
		if character == '\\' {
			index++
			if index == len(path) {
				return "", fmt.Errorf("JSON mutation path ends in an escape")
			}
			part.WriteByte(path[index])
			start = false
			continue
		}
		if character == '.' {
			if err := finish(); err != nil {
				return "", err
			}
			continue
		}
		if start && character == ':' {
			forced = true
			start = false
			continue
		}
		if strings.ContainsRune("|#@*?[]{}()!", rune(character)) {
			return "", fmt.Errorf("JSON mutation paths require literal fields and array indices; escape special key characters")
		}
		part.WriteByte(character)
		start = false
	}
	if err := finish(); err != nil {
		return "", err
	}
	return strings.Join(parts, "."), nil
}
