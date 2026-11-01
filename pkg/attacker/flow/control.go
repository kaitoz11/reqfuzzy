package flow

import (
	"context"
	"fmt"
	"math"
)

const MaxStepVisits = 1_000_000

type VisitInfo struct {
	Step         string
	Visit, Limit int
}
type navigationKey struct{}
type navigation struct {
	info     VisitInfo
	allowed  map[string]bool
	selected *string
}

func VisitLimit(step Step) int {
	if step.MaxVisits == nil {
		return 1
	}
	return *step.MaxVisits
}

func RequestUpperBound(definition Flow) (int64, error) {
	var total int64
	for _, step := range definition.Steps {
		limit := VisitLimit(step)
		if limit < 1 || limit > MaxStepVisits {
			return 0, fmt.Errorf("step %q has an invalid visit limit", step.ID)
		}
		if total > math.MaxInt64-int64(limit) {
			return 0, fmt.Errorf("flow request bound overflows")
		}
		total += int64(limit)
	}
	return total, nil
}

func CurrentVisit(ctx context.Context) (VisitInfo, bool) {
	control, ok := ctx.Value(navigationKey{}).(*navigation)
	if !ok {
		return VisitInfo{}, false
	}
	return control.info, true
}

func CheckNext(ctx context.Context, target string) error {
	control, ok := ctx.Value(navigationKey{}).(*navigation)
	if !ok {
		return fmt.Errorf("flow navigation requires an active visit")
	}
	if !control.allowed[target] {
		return fmt.Errorf("step %q does not declare the requested next destination", control.info.Step)
	}
	return nil
}

func SetNext(ctx context.Context, target string) error {
	if err := CheckNext(ctx, target); err != nil {
		return err
	}
	control := ctx.Value(navigationKey{}).(*navigation)
	control.selected = &target
	return nil
}

func visitContext(ctx context.Context, step Step, visit int, defaultNext string) (context.Context, *navigation) {
	control := &navigation{info: VisitInfo{step.ID, visit, VisitLimit(step)}, allowed: map[string]bool{defaultNext: true}}
	for _, target := range step.Routes {
		control.allowed[target] = true
	}
	return context.WithValue(ctx, navigationKey{}, control), control
}

func acceptsStatus(step Step, status int) bool {
	if step.ExpectStatus != nil {
		return status == *step.ExpectStatus
	}
	if len(step.ExpectStatuses) == 0 {
		return true
	}
	for _, candidate := range step.ExpectStatuses {
		if status == candidate {
			return true
		}
	}
	return false
}
