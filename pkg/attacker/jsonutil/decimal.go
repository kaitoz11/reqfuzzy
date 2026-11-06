package jsonutil

import (
	"bytes"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/tidwall/gjson"
)

type decimal struct {
	coefficient *big.Int
	scale       int
}

func parseDecimal(raw []byte) (decimal, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) > 4096 || !gjson.ValidBytes(raw) || gjson.ParseBytes(raw).Type != gjson.Number {
		return decimal{}, fmt.Errorf("arithmetic requires supported JSON numbers")
	}
	text := string(raw)
	exponent := 0
	if i := strings.IndexAny(text, "eE"); i >= 0 {
		var err error
		exponent, err = strconv.Atoi(text[i+1:])
		if err != nil || exponent < -10000 || exponent > 10000 {
			return decimal{}, fmt.Errorf("numeric exponent exceeds supported range")
		}
		text = text[:i]
	}
	scale := -exponent
	if i := strings.IndexByte(text, '.'); i >= 0 {
		scale += len(text) - i - 1
		text = text[:i] + text[i+1:]
	}
	coefficient, ok := new(big.Int).SetString(text, 10)
	if !ok {
		return decimal{}, fmt.Errorf("invalid decimal coefficient")
	}
	return decimal{coefficient, scale}, nil
}

// Arithmetic preserves decimal values without an intermediate float64.
func Arithmetic(left, right []byte, action string) ([]byte, error) {
	a, err := parseDecimal(left)
	if err != nil {
		return nil, err
	}
	b, err := parseDecimal(right)
	if err != nil {
		return nil, err
	}
	var value decimal
	switch action {
	case "add":
		scale := a.scale
		if b.scale > scale {
			scale = b.scale
		}
		align := func(number decimal) *big.Int {
			result := new(big.Int).Set(number.coefficient)
			if shift := scale - number.scale; shift > 0 {
				result.Mul(result, new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(shift)), nil))
			}
			return result
		}
		value = decimal{new(big.Int).Add(align(a), align(b)), scale}
	case "multiply":
		value = decimal{new(big.Int).Mul(a.coefficient, b.coefficient), a.scale + b.scale}
	default:
		return nil, fmt.Errorf("unsupported arithmetic action")
	}
	if value.coefficient.Sign() == 0 {
		return []byte("0"), nil
	}
	negative := value.coefficient.Sign() < 0
	digits := new(big.Int).Abs(value.coefficient).String()
	trimmed := strings.TrimRight(digits, "0")
	value.scale -= len(digits) - len(trimmed)
	digits = trimmed
	if len(digits) > 4096 {
		return nil, fmt.Errorf("arithmetic result exceeds supported precision")
	}
	var result string
	if value.scale <= 0 && len(digits)-value.scale <= 4096 {
		result = digits + strings.Repeat("0", -value.scale)
	} else if value.scale > 0 && value.scale+2 <= 4096 {
		if value.scale < len(digits) {
			result = digits[:len(digits)-value.scale] + "." + digits[len(digits)-value.scale:]
		} else {
			result = "0." + strings.Repeat("0", value.scale-len(digits)) + digits
		}
	} else {
		result = digits + "e" + strconv.Itoa(-value.scale)
	}
	if negative {
		result = "-" + result
	}
	if len(result) > 4096 {
		return nil, fmt.Errorf("arithmetic result exceeds supported precision")
	}
	if _, err := parseDecimal([]byte(result)); err != nil {
		return nil, err
	}
	return []byte(result), nil
}
