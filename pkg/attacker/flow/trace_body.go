package flow

import (
	"io"
	"net/http"
	"sync"

	"github.com/imroc/req/v3"
)

const maxTraceBodyBytes = 16 << 20

type recordedBody struct {
	source    io.ReadCloser
	mutex     sync.Mutex
	data      []byte
	count     int64
	eof       bool
	truncated bool
}

func (b *recordedBody) Read(buffer []byte) (int, error) {
	n, err := b.source.Read(buffer)
	b.mutex.Lock()
	b.count += int64(n)
	room := maxTraceBodyBytes - len(b.data)
	if n > room {
		b.data = append(b.data, buffer[:room]...)
		b.truncated = true
	} else {
		b.data = append(b.data, buffer[:n]...)
	}
	if err == io.EOF {
		b.eof = true
	}
	b.mutex.Unlock()
	return n, err
}
func (b *recordedBody) Close() error { return b.source.Close() }

type bodyAttempt struct {
	mutex        sync.Mutex
	raw          *http.Request
	bodies       []*recordedBody
	initial      *recordedBody
	initialEmpty bool
	unchanged    bool
	successful   bool
}

func (a *bodyAttempt) wrap(source io.ReadCloser) *recordedBody {
	body := &recordedBody{source: source}
	a.mutex.Lock()
	a.bodies = append(a.bodies, body)
	a.mutex.Unlock()
	return body
}

type bodyRecorder struct {
	mutex    sync.Mutex
	attempts []*bodyAttempt
}

func (r *bodyRecorder) observe(raw *http.Request, next http.RoundTripper) (*http.Response, error) {
	attempt := &bodyAttempt{raw: raw}
	r.mutex.Lock()
	r.attempts = append(r.attempts, attempt)
	r.mutex.Unlock()
	if raw.Body == nil || raw.Body == http.NoBody {
		attempt.initialEmpty = true
	} else {
		attempt.initial = attempt.wrap(raw.Body)
		raw.Body = attempt.initial
	}
	if factory := raw.GetBody; factory != nil {
		raw.GetBody = func() (io.ReadCloser, error) {
			source, err := factory()
			if err != nil || source == nil {
				return source, err
			}
			return attempt.wrap(source), nil
		}
	}
	response, err := next.RoundTrip(raw)
	attempt.mutex.Lock()
	attempt.successful = err == nil && response != nil
	attempt.unchanged = (attempt.initialEmpty && (raw.Body == nil || raw.Body == http.NoBody)) || raw.Body == attempt.initial
	attempt.mutex.Unlock()
	return response, err
}

func (a *bodyAttempt) body() ([]byte, bool) {
	a.mutex.Lock()
	bodies := append([]*recordedBody(nil), a.bodies...)
	unchanged := a.unchanged
	successful := a.successful
	initial := a.initial
	initialEmpty := a.initialEmpty
	raw := a.raw
	a.mutex.Unlock()
	if !unchanged {
		return nil, false
	}
	var selected []byte
	consumed := 0
	complete := false
	actual := false
	for _, body := range bodies {
		body.mutex.Lock()
		if body.count > 0 || body.eof {
			consumed++
			selected = append([]byte(nil), body.data...)
			complete = !body.truncated && (body.eof || (successful && raw.ContentLength >= 0 && body.count == raw.ContentLength))
			actual = body == initial
		}
		body.mutex.Unlock()
	}
	if consumed == 1 && complete && actual {
		return selected, true
	}
	if consumed == 0 && initialEmpty && raw.ContentLength == 0 {
		return nil, true
	}
	return nil, false
}

func (r *bodyRecorder) snapshot() *RequestSnapshot {
	r.mutex.Lock()
	if len(r.attempts) == 0 {
		r.mutex.Unlock()
		return nil
	}
	attempt := r.attempts[len(r.attempts)-1]
	r.mutex.Unlock()
	attempt.mutex.Lock()
	raw := attempt.raw
	attempt.mutex.Unlock()
	if raw == nil || raw.URL == nil {
		return nil
	}
	headers := raw.Header.Clone()
	delete(headers, req.HeaderOderKey)
	delete(headers, req.PseudoHeaderOderKey)
	body, known := attempt.body()
	source := "captured"
	if !known {
		source = "unavailable"
	}
	return &RequestSnapshot{Method: raw.Method, RawURL: raw.URL.String(), Host: raw.Host, Query: raw.URL.Query(), Headers: headers, Body: body, BodySource: source}
}
