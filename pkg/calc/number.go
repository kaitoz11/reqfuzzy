package calc

import (
	"fmt"
	"math"
)

func FormatNumber(num float64) string {
	intOfNum := int(num)

	if num == float64(intOfNum) {
		return fmt.Sprintf("%d", intOfNum)
	}

	return fmt.Sprintf("%g", num)
}

func CalculateAmountDelta(preAmt, postAmt float64, f int) float64 {
	a := math.Pow10(f)
	return float64(int(postAmt*a)-int(preAmt*a)) / a
}
