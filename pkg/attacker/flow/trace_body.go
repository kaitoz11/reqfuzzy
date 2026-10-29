package flow

import (
	"io"
	"net/http"
	"sync"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker"
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

type bodyRecorder struct {
	mutex  sync.Mutex
	bodies []*recordedBody
}

func recordBody(request attacker.Request) *bodyRecorder {
	recorder := &bodyRecorder{}
	factory := request.GetBody
	if factory == nil {
		return recorder
	}
	request.GetBody = func() (io.ReadCloser, error) {
		source, err := factory()
		if err != nil || source == nil {
			return source, err
		}
		body := &recordedBody{source: source}
		recorder.mutex.Lock()
		recorder.bodies = append(recorder.bodies, body)
		recorder.mutex.Unlock()
		return body, nil
	}
	return recorder
}

func (r *bodyRecorder) snapshot(raw *http.Request, successful bool) ([]byte, bool) {
	r.mutex.Lock()
	bodies := append([]*recordedBody(nil), r.bodies...)
	r.mutex.Unlock()
	var selected []byte
	consumed := 0
	complete := false
	for _, body := range bodies {
		body.mutex.Lock()
		if body.count > 0 || body.eof {
			consumed++
			selected = append([]byte(nil), body.data...)
			complete = !body.truncated && (body.eof || (successful && raw.ContentLength >= 0 && body.count == raw.ContentLength))
		}
		body.mutex.Unlock()
	}
	if consumed == 1 && complete {
		return selected, true
	}
	if consumed == 0 && (raw.Body == nil || raw.Body == http.NoBody) && raw.ContentLength == 0 {
		return nil, true
	}
	return nil, false
}
