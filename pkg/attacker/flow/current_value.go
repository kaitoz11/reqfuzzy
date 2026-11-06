package flow

import (
	"encoding/json"
	"fmt"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/jsonutil"
	"github.com/tidwall/gjson"
)

func CurrentMutationValue(request attacker.Request, location, path string) (Value, error) {
	if location == "json" {
		if err := jsonutil.ValidateUnique(request.Body); err != nil {
			return Value{}, fmt.Errorf("current JSON value is invalid or ambiguous")
		}
		lookup, err := jsonutil.MutationLookupPath(path)
		if err != nil {
			return Value{}, err
		}
		found := gjson.GetBytes(request.Body, lookup)
		if !found.Exists() || found.Type == gjson.JSON {
			return Value{}, fmt.Errorf("current mutation scalar is missing")
		}
		return ParseMutationValue([]byte(found.Raw))
	}
	value, err := existingValue(request, location, path, true)
	if err != nil {
		return Value{}, err
	}
	raw, _ := json.Marshal(value.Text)
	return Value{RawJSON: raw, Text: value.Text}, nil
}
