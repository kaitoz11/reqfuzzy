// Package script adapts synchronous JavaScript to reqfuzzy flow callbacks.
package script

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/dop251/goja"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
)

type Program struct {
	name    string
	code    *goja.Program
	timeout time.Duration
}

var errTimeout = errors.New("execution timed out")

func Compile(name, source string, timeout time.Duration) (*Program, error) {
	if timeout <= 0 {
		return nil, fmt.Errorf("script timeout must be positive")
	}
	code, err := goja.Compile(name, source, true)
	if err != nil {
		return nil, fmt.Errorf("compile script %s: %w", name, err)
	}
	return &Program{name: name, code: code, timeout: timeout}, nil
}

func (p *Program) runtime(ctx context.Context, action func(*goja.Runtime) error) (err error) {
	vm := goja.New()
	timer := time.AfterFunc(p.timeout, func() { vm.Interrupt(errTimeout) })
	stop := context.AfterFunc(ctx, func() { vm.Interrupt(ctx.Err()) })
	defer timer.Stop()
	defer stop()
	defer func() {
		if recovered := recover(); recovered != nil {
			switch value := recovered.(type) {
			case *goja.Exception:
				err = value
			case *goja.InterruptedError:
				err = value
			default:
				panic(recovered)
			}
		}
		if err != nil {
			err = fmt.Errorf("script %s: %w", p.name, err)
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	installBuiltins(vm)
	if _, err = vm.RunProgram(p.code); err != nil {
		return err
	}
	return action(vm)
}

func installBuiltins(vm *goja.Runtime) {
	_ = vm.Set("crypto", map[string]any{
		"sha256": func(text string) string { digest := sha256.Sum256([]byte(text)); return hex.EncodeToString(digest[:]) },
		"hmacSha256": func(key, text string) string {
			mac := hmac.New(sha256.New, []byte(key))
			_, _ = mac.Write([]byte(text))
			return hex.EncodeToString(mac.Sum(nil))
		},
	})
	_ = vm.Set("encoding", map[string]any{
		"base64Encode": func(text string) string { return base64.StdEncoding.EncodeToString([]byte(text)) },
		"base64Decode": func(text string) (string, error) {
			decoded, err := base64.StdEncoding.DecodeString(text)
			if err != nil {
				return "", fmt.Errorf("invalid base64")
			}
			if !utf8.Valid(decoded) {
				return "", fmt.Errorf("decoded value is not UTF-8")
			}
			return string(decoded), nil
		},
	})
}

func callback(vm *goja.Runtime, name string) (goja.Callable, error) {
	fn, ok := goja.AssertFunction(vm.Get(name))
	if !ok {
		return nil, fmt.Errorf("callback %s is not defined", name)
	}
	return fn, nil
}

func (p *Program) Check(name string) error {
	return p.CheckContext(context.Background(), name)
}

func (p *Program) CheckContext(ctx context.Context, name string) error {
	if name != "beforeSend" && name != "afterResponse" {
		return fmt.Errorf("unknown callback %q", name)
	}
	return p.runtime(ctx, func(vm *goja.Runtime) error { _, err := callback(vm, name); return err })
}

func invoke(vm *goja.Runtime, name string, ctx *goja.Object) error {
	fn, err := callback(vm, name)
	if err != nil {
		return err
	}
	returned, err := fn(goja.Undefined(), ctx)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if !goja.IsUndefined(returned) && !goja.IsNull(returned) {
		return fmt.Errorf("%s must be synchronous and return no value", name)
	}
	return nil
}

func (p *Program) BeforeSend(request attacker.Request, variables flow.Variables) error {
	if !utf8.Valid(request.Body) {
		return fmt.Errorf("script %s: request body is not UTF-8", p.name)
	}
	staged := cloneVariables(variables)
	return p.runtime(request.Context(), func(vm *goja.Runtime) error {
		jsRequest, headers, err := requestObject(vm, request)
		if err != nil {
			return err
		}
		ctx := vm.NewObject()
		_ = ctx.Set("request", jsRequest)
		_ = ctx.Set("vars", variablesObject(vm, staged))
		if err := invoke(vm, "beforeSend", ctx); err != nil {
			return err
		}
		if err := applyRequest(jsRequest, headers, request); err != nil {
			return err
		}
		commitVariables(variables, staged)
		return nil
	})
}

func (p *Program) AfterResponse(response attacker.Response, variables flow.Variables) error {
	if response.Response == nil || response.Response.Response == nil {
		return fmt.Errorf("script %s: response is missing", p.name)
	}
	if !utf8.Valid(response.Bytes()) {
		return fmt.Errorf("script %s: response body is not UTF-8", p.name)
	}
	staged := cloneVariables(variables)
	ctx := context.Background()
	if response.Request != nil {
		ctx = response.Request.Context()
	}
	return p.runtime(ctx, func(vm *goja.Runtime) error {
		object := vm.NewObject()
		_ = object.Set("status", response.StatusCode)
		_ = object.Set("body", string(response.Bytes()))
		_ = object.Set("getHeader", func(name string) string { return response.Header.Get(name) })
		jsContext := vm.NewObject()
		_ = jsContext.Set("response", object)
		_ = jsContext.Set("vars", variablesObject(vm, staged))
		if err := invoke(vm, "afterResponse", jsContext); err != nil {
			return err
		}
		commitVariables(variables, staged)
		return nil
	})
}
