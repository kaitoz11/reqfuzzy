package script

import (
	"context"
	"fmt"

	"github.com/dop251/goja"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
)

func flowObject(vm *goja.Runtime, ctx context.Context, navigate bool) (*goja.Object, func() error) {
	object := vm.NewObject()
	info, _ := flow.CurrentVisit(ctx)
	_ = object.Set("step", info.Step)
	_ = object.Set("visit", info.Visit)
	_ = object.Set("limit", info.Limit)
	var selected *string
	choose := func(target string) error {
		if err := flow.CheckNext(ctx, target); err != nil {
			return err
		}
		selected = &target
		return nil
	}
	if navigate {
		_ = object.Set("next", func(value goja.Value) error {
			target, ok := value.Export().(string)
			if !ok {
				return fmt.Errorf("flow.next needs a step name")
			}
			return choose(target)
		})
		_ = object.Set("stop", func() error { return choose("") })
	}
	return object, func() error {
		if selected != nil {
			return flow.SetNext(ctx, *selected)
		}
		return nil
	}
}
