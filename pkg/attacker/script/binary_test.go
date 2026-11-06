package script_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
)

func TestBinaryRequestRepresentationsAndAtomicConflicts(t *testing.T) {
	original := []byte{0, 255, 1}
	for _, tc := range []struct {
		name, source string
		want         []byte
		failure      bool
	}{
		{"unchanged", `if(ctx.request.body!==null||ctx.request.bodyBase64!=="AP8B")throw Error("bytes");`, original, false},
		{"base64 edit", `ctx.request.bodyBase64="Av4=";`, []byte{2, 254}, false},
		{"text edit", `ctx.request.body="hello";`, []byte("hello"), false},
		{"consistent", `ctx.request.body="hello";ctx.request.bodyBase64="aGVsbG8=";`, []byte("hello"), false},
		{"conflict", `ctx.request.body="hello";ctx.request.bodyBase64="Av4=";`, nil, true},
		{"deleted", `delete ctx.request.bodyBase64;`, nil, true},
		{"invalid", `ctx.request.bodyBase64="?";`, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := request(t)
			r.SetBodyBytes(append([]byte(nil), original...))
			vars := flow.Variables{}
			p := compile(t, `function beforeSend(ctx){ctx.request.method="PUT";ctx.vars.set("staged",true);`+tc.source+`}`)
			err := p.BeforeSend(r, vars)
			if tc.failure {
				if err == nil || !bytes.Equal(r.Body, original) || r.Method != "POST" || len(vars) != 0 {
					t.Fatalf("atomic failure err=%v request=%v vars=%v", err, r, vars)
				}
				return
			}
			if err != nil || !bytes.Equal(r.Body, tc.want) {
				t.Fatalf("err=%v body=%v want=%v", err, r.Body, tc.want)
			}
		})
	}
}

func TestByteCryptoAcceptsExplicitBinaryAndRejectsInvalidBase64(t *testing.T) {
	p := compile(t, `function beforeSend(ctx){ctx.request.setHeader("X-Hash",crypto.sha256Bytes(ctx.request.bodyBase64));ctx.request.setHeader("X-Mac",crypto.hmacSha256Bytes(encoding.base64Encode("key"),ctx.request.bodyBase64));}`)
	r := request(t)
	r.SetBodyBytes([]byte{0, 255, 1})
	if err := p.BeforeSend(r, flow.Variables{}); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(r.Body)
	mac := hmac.New(sha256.New, []byte("key"))
	mac.Write(r.Body)
	if r.Headers.Get("X-Hash") != hex.EncodeToString(digest[:]) || r.Headers.Get("X-Mac") != hex.EncodeToString(mac.Sum(nil)) {
		t.Fatal("binary digest mismatch")
	}
	for _, source := range []string{`crypto.sha256Bytes("?")`, `crypto.hmacSha256Bytes("?","AA==")`, `crypto.hmacSha256Bytes("AA==","?")`} {
		p := compile(t, `function beforeSend(ctx){`+source+`;}`)
		if err := p.BeforeSend(request(t), flow.Variables{}); err == nil {
			t.Fatal("bad base64 accepted")
		}
	}
}

func TestBinaryResponseSupportsReadOnlyBytesAndRollsBackOnInvalidEdit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte{0, 255, 1}) }))
	defer server.Close()
	client := attacker.NewHClient()
	client.UseBaseURL(server.URL)
	r, err := client.ParseRawRequest([]byte("GET / HTTP/1.1\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.SendRequest(r)
	if err != nil {
		t.Fatal(err)
	}
	p := compile(t, `function afterResponse(ctx){if(ctx.response.body!==null||ctx.response.bodyBase64!=="AP8B")throw Error("binary response");ctx.vars.set("seen",true);}`)
	vars := flow.Variables{}
	if err := p.AfterResponse(response, vars); err != nil || vars["seen"].Text != "true" {
		t.Fatalf("response err=%v vars=%v", err, vars)
	}
	p = compile(t, `function afterResponse(ctx){ctx.vars.set("partial",true);ctx.response.bodyBase64="AA==";}`)
	vars = flow.Variables{}
	if err := p.AfterResponse(response, vars); err == nil || len(vars) != 0 {
		t.Fatalf("read-only failure err=%v vars=%v", err, vars)
	}
}
func TestTextRequestCanBecomeBinaryWithoutLoss(t *testing.T) {
	r := request(t)
	p := compile(t, `function beforeSend(ctx){ctx.request.bodyBase64="AP8B";}`)
	if err := p.BeforeSend(r, flow.Variables{}); err != nil || !bytes.Equal(r.Body, []byte{0, 255, 1}) {
		t.Fatalf("binary edit err=%v body=%v", err, r.Body)
	}
}
