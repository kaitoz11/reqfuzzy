package campaign

import (
	"fmt"
	"math"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
)

func RequestUpperBound(main flow.Flow, verification *flow.Flow, cases int) (int64, error) {
	if cases < 0 || int64(cases) == math.MaxInt64 {
		return 0, fmt.Errorf("invalid trial count")
	}
	bound, err := flow.RequestUpperBound(main)
	if err != nil {
		return 0, err
	}
	if verification != nil {
		extra, err := flow.RequestUpperBound(*verification)
		if err != nil {
			return 0, err
		}
		if bound > math.MaxInt64-extra {
			return 0, fmt.Errorf("trial request bound overflows")
		}
		bound += extra
	}
	trials := int64(cases) + 1
	if bound > math.MaxInt64/trials {
		return 0, fmt.Errorf("campaign request bound overflows")
	}
	return bound * trials, nil
}
