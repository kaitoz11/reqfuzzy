package jsonutil_test

import (
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/jsonutil"
	"testing"
)

func TestArithmeticRemainsInsideSupportedNumericBounds(t *testing.T) {
	if _, err := jsonutil.Arithmetic([]byte("1e10000"), []byte("1e10000"), "multiply"); err == nil {
		t.Fatal("arithmetic emitted a result outside its supported exponent range")
	}
}
