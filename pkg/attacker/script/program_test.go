package script_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/script"
)

func request(t *testing.T) attacker.Request {
	t.Helper()
	r, err := attacker.NewHClient().ParseRawRequest([]byte("POST /create HTTP/1.1\r\nHost: example.test\r\nX-Signature: stale\r\nContent-Type: application/json\r\n\r\n{\"amount\":10}"))
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func compile(t *testing.T, source string) *script.Program {
	t.Helper()
	p, err := script.Compile("test.js", source, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestBeforeScriptMorphsAndSignsFinalBody(t *testing.T) {
	p := compile(t, `function beforeSend(ctx){var body=JSON.parse(ctx.request.body);body.amount=ctx.vars.get("amount");ctx.request.body=JSON.stringify(body);ctx.request.setHeader("X-Signature",crypto.hmacSha256("key",ctx.request.body));ctx.vars.set("sent",true);}`)
	if err := p.Check("beforeSend"); err != nil {
		t.Fatal(err)
	}
	r := request(t)
	v, _ := flow.ParseValue([]byte("99"))
	vars := flow.Variables{"amount": v}
	if err := p.BeforeSend(r, vars); err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, []byte("key"))
	mac.Write([]byte(`{"amount":99}`))
	if string(r.Body) != `{"amount":99}` || r.Headers.Get("X-Signature") != hex.EncodeToString(mac.Sum(nil)) || vars["sent"].Text != "true" {
		t.Fatalf("body=%s headers=%v vars=%v", r.Body, r.Headers, vars)
	}
}

func TestScriptFailureRollsBackEdits(t *testing.T) {
	p := compile(t, `function beforeSend(ctx){ctx.request.body="changed";ctx.vars.set("partial",1);throw new Error("stop");}`)
	r := request(t)
	vars := flow.Variables{}
	if err := p.BeforeSend(r, vars); err == nil {
		t.Fatal("throw accepted")
	}
	if string(r.Body) != `{"amount":10}` || len(vars) != 0 {
		t.Fatalf("partial script edits leaked: body=%s vars=%v", r.Body, vars)
	}
}

func TestScriptDeadlineIncludesTopLevel(t *testing.T) {
	for _, source := range []string{`for(;;){} function beforeSend(ctx){}`, `function beforeSend(ctx){for(;;){}}`} {
		p, err := script.Compile("loop.js", source, 20*time.Millisecond)
		if err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		err = p.BeforeSend(request(t), flow.Variables{})
		if err == nil || !strings.Contains(err.Error(), "timed out") || time.Since(started) > 2*time.Second {
			t.Fatalf("deadline err=%v elapsed=%s", err, time.Since(started))
		}
	}
}

func TestRawVariablesPreserveLargeNumbers(t *testing.T) {
	p := compile(t, `function beforeSend(ctx){ctx.vars.setRaw("copy",ctx.vars.getRaw("id"));ctx.request.body='{"id":'+ctx.vars.getRaw("id")+'}';}`)
	r := request(t)
	v, _ := flow.ParseValue([]byte("9007199254740993"))
	vars := flow.Variables{"id": v}
	if err := p.BeforeSend(r, vars); err != nil {
		t.Fatal(err)
	}
	if string(r.Body) != `{"id":9007199254740993}` || string(vars["copy"].RawJSON) != "9007199254740993" {
		t.Fatalf("precision lost: %s %v", r.Body, vars)
	}
	unsafe := compile(t, `function beforeSend(ctx){ctx.vars.get("id");}`)
	if err := unsafe.BeforeSend(r, vars); err == nil {
		t.Fatal("unsafe Number conversion silently accepted")
	}
}

func TestScriptRejectsInvalidEditsAndAsyncResult(t *testing.T) {
	cases := []string{`function beforeSend(ctx){ctx.request.setHeader("X-Test","bad\nvalue");}`, `function beforeSend(ctx){ctx.request.url="https://other.test/";}`, `function beforeSend(ctx){ctx.request.body={};}`, `function beforeSend(ctx){return Promise.resolve(1);}`, `function beforeSend(ctx){ctx.vars.set("obj",{});}`}
	for _, source := range cases {
		p := compile(t, source)
		if err := p.BeforeSend(request(t), flow.Variables{}); err == nil {
			t.Fatalf("invalid script accepted: %s", source)
		}
	}
}

func TestEachInvocationHasFreshJavaScriptGlobals(t *testing.T) {
	p := compile(t, `var count=0;function beforeSend(ctx){count++;ctx.request.setHeader("X-Count",String(count));}`)
	for range 2 {
		r := request(t)
		if err := p.BeforeSend(r, flow.Variables{}); err != nil {
			t.Fatal(err)
		}
		if r.Headers.Get("X-Count") != "1" {
			t.Fatal("JS globals crossed invocations")
		}
	}
}

func TestScriptSeesEffectiveQueryAndReplacesIt(t *testing.T) {
	p := compile(t, `function beforeSend(ctx){ctx.request.url=ctx.request.url.replace("added=old","added=new");}`)
	r := request(t)
	r.SetQueryParam("added", "old")
	if err := p.BeforeSend(r, flow.Variables{}); err != nil {
		t.Fatal(err)
	}
	if r.RawURL != "/create?added=new" || len(r.QueryParams) != 0 {
		t.Fatalf("url=%q extra queries=%v", r.RawURL, r.QueryParams)
	}
}

func TestThrowingRequestGetterReturnsError(t *testing.T) {
	p := compile(t, `function beforeSend(ctx){Object.defineProperty(ctx.request,"body",{get:function(){throw new Error("getter failed");}});}`)
	if err := p.BeforeSend(request(t), flow.Variables{}); err == nil {
		t.Fatal("throwing getter accepted")
	}
}

func TestScriptPreflightHonorsCallerCancellation(t *testing.T) {
	p, err := script.Compile("loop.js", `for(;;){} function beforeSend(ctx){}`, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := p.CheckContext(ctx, "beforeSend"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("preflight err=%v", err)
	}
}
