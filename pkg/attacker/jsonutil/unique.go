// Package jsonutil contains shared strict JSON rules used by mutation and observation.
package jsonutil

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// ValidateUnique rejects invalid JSON and duplicate object keys, including nested ones.
func ValidateUnique(data []byte) error {
	if !json.Valid(data) {
		return fmt.Errorf("invalid JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if ambiguous(decoder) {
		return fmt.Errorf("duplicate or ambiguous JSON object keys")
	}
	return nil
}
func ambiguous(decoder *json.Decoder) bool {
	token, err := decoder.Token()
	if err != nil {
		return true
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return false
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			token, err := decoder.Token()
			if err != nil {
				return true
			}
			key, ok := token.(string)
			if !ok || seen[key] {
				return true
			}
			seen[key] = true
			if ambiguous(decoder) {
				return true
			}
		}
		_, err := decoder.Token()
		return err != nil
	case '[':
		for decoder.More() {
			if ambiguous(decoder) {
				return true
			}
		}
		_, err := decoder.Token()
		return err != nil
	default:
		return true
	}
}
