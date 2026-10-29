package flow

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestMultipleConsumedBodySourcesCannotClaimSingleSentBody(t *testing.T) {
	for _, extraRead := range []bool{false, true} {
		raw, _ := http.NewRequest("POST", "http://example.test/", strings.NewReader("abc"))
		recorder := &bodyRecorder{}
		_, err := recorder.observe(raw, roundTripFunc(func(request *http.Request) (*http.Response, error) {
			io.ReadAll(request.Body)
			request.Body.Close()
			if extraRead {
				second, err := request.GetBody()
				if err != nil {
					return nil, err
				}
				io.ReadAll(second)
				second.Close()
			}
			return &http.Response{StatusCode: 200, Body: http.NoBody, Request: request}, nil
		}))
		if err != nil {
			t.Fatal(err)
		}
		sent := recorder.snapshot()
		if !extraRead {
			if sent.BodySource != "captured" || string(sent.Body) != "abc" {
				t.Fatalf("actual body unavailable: %#v", sent)
			}
		} else if sent.BodySource != "unavailable" || len(sent.Body) != 0 {
			t.Fatal("multiple consumed sources were reported as one actual body")
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }
