package flow

import (
	"io"
	"net/http"
	"testing"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker"
)

func TestMultipleConsumedBodySourcesCannotClaimSingleSentBody(t *testing.T) {
	request, err := attacker.NewHClient().ParseRawRequest([]byte("POST / HTTP/1.1\r\n\r\nabc"))
	if err != nil {
		t.Fatal(err)
	}
	recorder := recordBody(request)
	first, err := request.GetBody()
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(first)
	first.Close()
	raw := &http.Request{ContentLength: 3}
	if body, known := recorder.snapshot(raw, true); !known || string(body) != "abc" {
		t.Fatalf("one consumed body not captured: %q %t", body, known)
	}
	second, err := request.GetBody()
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(second)
	second.Close()
	if body, known := recorder.snapshot(raw, true); known || len(body) != 0 {
		t.Fatal("multiple consumed sources were reported as one actual body")
	}
}
