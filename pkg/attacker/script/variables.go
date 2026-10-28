package script

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"strconv"

	"github.com/dop251/goja"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
)

const maxSafeNumber = 9007199254740991

func cloneVariables(values flow.Variables) flow.Variables {
	result := make(flow.Variables, len(values))
	for name, value := range values {
		result[name] = flow.Value{Text: value.Text, RawJSON: bytes.Clone(value.RawJSON)}
	}
	return result
}
func commitVariables(target, source flow.Variables) {
	for key := range target {
		delete(target, key)
	}
	for key, value := range source {
		target[key] = value
	}
}

func variablesObject(vm *goja.Runtime, values flow.Variables) *goja.Object {
	object := vm.NewObject()
	_ = object.Set("getRaw", func(name string) (string, error) {
		value, ok := values[name]
		if !ok {
			return "", fmt.Errorf("variable %q is missing", name)
		}
		return string(value.RawJSON), nil
	})
	_ = object.Set("get", func(name string) (any, error) {
		value, ok := values[name]
		if !ok {
			return nil, fmt.Errorf("variable %q is missing", name)
		}
		decoder := json.NewDecoder(bytes.NewReader(value.RawJSON))
		decoder.UseNumber()
		var decoded any
		if err := decoder.Decode(&decoded); err != nil {
			return nil, err
		}
		if number, ok := decoded.(json.Number); ok {
			f, err := strconv.ParseFloat(number.String(), 64)
			if err != nil || math.IsInf(f, 0) || math.Abs(f) > maxSafeNumber {
				return nil, fmt.Errorf("variable %q is not a safe JavaScript number; use getRaw", name)
			}
			return f, nil
		}
		return decoded, nil
	})
	_ = object.Set("setRaw", func(name, raw string) error {
		if name == "" {
			return fmt.Errorf("variable name is required")
		}
		value, err := flow.ParseValue([]byte(raw))
		if err != nil {
			return err
		}
		values[name] = value
		return nil
	})
	_ = object.Set("set", func(name string, value goja.Value) error {
		if name == "" {
			return fmt.Errorf("variable name is required")
		}
		if _, object := value.(*goja.Object); object {
			return fmt.Errorf("variables must be scalar")
		}
		exported := value.Export()
		switch typed := exported.(type) {
		case string, bool:
		case int64:
			if typed > maxSafeNumber || typed < -maxSafeNumber {
				return fmt.Errorf("unsafe JavaScript number; use setRaw")
			}
		case float64:
			if math.IsNaN(typed) || math.IsInf(typed, 0) || math.Abs(typed) > maxSafeNumber {
				return fmt.Errorf("unsafe JavaScript number; use setRaw")
			}
		default:
			return fmt.Errorf("variables must be strings, numbers, or booleans")
		}
		raw, err := json.Marshal(exported)
		if err != nil {
			return err
		}
		parsed, err := flow.ParseValue(raw)
		if err != nil {
			return err
		}
		values[name] = parsed
		return nil
	})
	return object
}
