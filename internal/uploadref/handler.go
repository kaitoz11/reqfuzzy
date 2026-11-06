// Package uploadref implements a local upload API independently of reqfuzzy's
// parser and mutation engine. It never writes uploaded files to disk.
package uploadref

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"path"
	"strings"
	"sync"
)

type session struct {
	nonce, key, filename string
	used, unsafe         bool
	size                 int
}
type API struct {
	mu         sync.Mutex
	next       int
	sessions   map[string]*session
	vulnerable bool
}

func New(vulnerable bool) *API { return &API{sessions: map[string]*session{}, vulnerable: vulnerable} }
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if r.Method == "POST" && r.URL.Path == "/session" {
		a.next++
		token := fmt.Sprintf("upload-token-%06d", a.next)
		s := &session{nonce: fmt.Sprintf("upload-nonce-%06d", a.next), key: fmt.Sprintf("upload-key-%06d", a.next)}
		a.sessions[token] = s
		json.NewEncoder(w).Encode(map[string]any{"token": token, "nonce": s.nonce, "signing_key": s.key, "filename": "note.bin", "media_type": "application/octet-stream", "file_data": base64.StdEncoding.EncodeToString([]byte{0, 255, 1, 'f', 'i', 'l', 'e'})})
		return
	}
	s := a.sessions[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
	if s == nil {
		http.Error(w, "session", 401)
		return
	}
	if r.Method == "GET" && r.URL.Path == "/state" {
		json.NewEncoder(w).Encode(map[string]any{"unsafe": s.unsafe, "filename": s.filename, "size": s.size})
		return
	}
	if r.Method != "POST" || r.URL.Path != "/upload" {
		http.NotFound(w, r)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20+1))
	if err != nil || len(body) > 1<<20 {
		http.Error(w, "body", 413)
		return
	}
	mac := hmac.New(sha256.New, []byte(s.key))
	mac.Write(body)
	supplied, err := hex.DecodeString(r.Header.Get("X-Signature"))
	if err != nil || !hmac.Equal(supplied, mac.Sum(nil)) {
		http.Error(w, "signature", 401)
		return
	}
	// The server uses the standard HTTP multipart parser rather than the tool's.
	r.Body = io.NopCloser(strings.NewReader(string(body)))
	r.ContentLength = int64(len(body))
	reader, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "multipart", 400)
		return
	}
	var nonce, filename string
	var data []byte
	seen := map[string]bool{}
	for {
		part, err := reader.NextRawPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(w, "part", 400)
			return
		}
		name := part.FormName()
		if seen[name] {
			http.Error(w, "duplicate", 400)
			return
		}
		seen[name] = true
		value, err := io.ReadAll(part)
		if err != nil {
			http.Error(w, "data", 400)
			return
		}
		switch name {
		case "nonce":
			nonce = string(value)
		case "file":
			_, params, err := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
			if err != nil {
				http.Error(w, "filename", 400)
				return
			}
			filename = params["filename"]
			data = value
		}
	}
	if s.used || nonce != s.nonce {
		http.Error(w, "nonce", 409)
		return
	}
	s.used = true
	unsafe := filename == "" || path.Base(filename) != filename || strings.ContainsAny(filename, "\\") || filename == "." || filename == ".."
	if unsafe && !a.vulnerable {
		http.Error(w, "unsafe filename", 422)
		return
	}
	s.filename = filename
	s.size = len(data)
	s.unsafe = unsafe
	// A binary acknowledgment exercises status-only response scripting.
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(201)
	w.Write([]byte{0, 255, 1})
}
