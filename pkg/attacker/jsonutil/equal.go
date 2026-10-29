package jsonutil

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

func number(raw []byte) (*big.Rat, error) {
	if len(raw) > 4096 {
		return nil, fmt.Errorf("numeric operand exceeds supported precision")
	}
	text := string(raw)
	if index := strings.IndexAny(text, "eE"); index >= 0 {
		exponent, err := strconv.ParseInt(text[index+1:], 10, 32)
		if err != nil || exponent > 10000 || exponent < -10000 {
			return nil, fmt.Errorf("numeric exponent exceeds supported range")
		}
	}
	parsed, ok := new(big.Rat).SetString(text)
	if !ok {
		return nil, fmt.Errorf("invalid numeric operand")
	}
	return parsed, nil
}
func CompareNumbers(left, right []byte) (int, error) {
	a, err := number(left)
	if err != nil {
		return 0, err
	}
	b, err := number(right)
	if err != nil {
		return 0, err
	}
	return a.Cmp(b), nil
}

// EqualJSON compares typed JSON structures without rounding numbers to float64.
func EqualJSON(left, right []byte) (bool, error) {
	if err := ValidateUnique(left); err != nil {
		return false, err
	}
	if err := ValidateUnique(right); err != nil {
		return false, err
	}
	decode := func(raw []byte) (any, error) {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		var value any
		err := decoder.Decode(&value)
		return value, err
	}
	a, err := decode(left)
	if err != nil {
		return false, err
	}
	b, err := decode(right)
	if err != nil {
		return false, err
	}
	return equal(a, b)
}
func equal(left, right any) (bool, error) {
	switch a := left.(type) {
	case nil:
		return right == nil, nil
	case string:
		b, ok := right.(string)
		return ok && a == b, nil
	case bool:
		b, ok := right.(bool)
		return ok && a == b, nil
	case json.Number:
		b, ok := right.(json.Number)
		if !ok {
			return false, nil
		}
		order, err := CompareNumbers([]byte(a), []byte(b))
		return order == 0 && err == nil, err
	case []any:
		b, ok := right.([]any)
		if !ok || len(a) != len(b) {
			return false, nil
		}
		for index := range a {
			same, err := equal(a[index], b[index])
			if err != nil || !same {
				return same, err
			}
		}
		return true, nil
	case map[string]any:
		b, ok := right.(map[string]any)
		if !ok || len(a) != len(b) {
			return false, nil
		}
		for key, value := range a {
			other, exists := b[key]
			if !exists {
				return false, nil
			}
			same, err := equal(value, other)
			if err != nil || !same {
				return same, err
			}
		}
		return true, nil
	}
	return false, fmt.Errorf("unsupported JSON value")
}
