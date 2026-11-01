package reference_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kaitoz11/reqfuzzy/internal/reference"
)

type pausedSessionWriter struct {
	*httptest.ResponseRecorder
	calls            int
	entered, release chan struct{}
}

func (w *pausedSessionWriter) Header() http.Header {
	w.calls++
	if w.calls == 2 {
		close(w.entered)
		<-w.release
	}
	return w.ResponseRecorder.Header()
}

func TestSessionResponseRetainsItsCreationCredentialSnapshot(t *testing.T) {
	handler := reference.NewHandler(reference.Options{RefreshOnce: true})
	writer := &pausedSessionWriter{ResponseRecorder: httptest.NewRecorder(), entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(writer, httptest.NewRequest("POST", "http://reference.test/session", nil))
		close(done)
	}()
	<-writer.entered
	refresh := httptest.NewRequest("POST", "http://reference.test/refresh", nil)
	refresh.AddCookie(&http.Cookie{Name: "reference_sid", Value: "1"})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, refresh)
	close(writer.release)
	<-done
	var session struct {
		Token string `json:"access_token"`
		Key   string `json:"signing_key"`
	}
	if err := json.Unmarshal(writer.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	if session.Token != "reference-token-1" || session.Key != "reference-signing-1" {
		t.Fatal("session credentials changed while its response was being constructed")
	}
}
