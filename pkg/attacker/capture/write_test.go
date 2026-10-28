package capture_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker/capture"
)

func TestWriteRequestsIsIdempotentAndRejectsConflict(t *testing.T) {
	parsed, err := capture.ParseHAR(sampleHAR())
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(t.TempDir(), "requests")
	first, err := parsed.WriteRequests(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 3 {
		t.Fatalf("paths = %d, want 3", len(first))
	}
	for _, exchange := range parsed.Exchanges {
		path := first[exchange.Name]
		if !filepath.IsAbs(path) || filepath.Dir(path) != directory || strings.ContainsAny(exchange.Name, `/\`) {
			t.Fatalf("unsafe generated request path %q", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, exchange.RequestRaw) {
			t.Fatalf("file %q differs from imported request", path)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("file %q mode = %o, want 600", path, info.Mode().Perm())
		}
	}
	second, err := parsed.WriteRequests(directory)
	if err != nil || len(second) != len(first) {
		t.Fatalf("idempotent write: paths=%v err=%v", second, err)
	}
	conflictPath := first[parsed.Exchanges[0].Name]
	if err := os.WriteFile(conflictPath, []byte("edited by operator"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := parsed.WriteRequests(directory); err == nil {
		t.Fatal("expected conflict when a generated request has different bytes")
	}
	data, err := os.ReadFile(conflictPath)
	if err != nil || string(data) != "edited by operator" {
		t.Fatalf("conflict file was overwritten: %q, %v", data, err)
	}
}

func TestWriteRequestsRejectsUnsafeName(t *testing.T) {
	archive := capture.Capture{Exchanges: []capture.Exchange{{Name: "../escape", RequestRaw: []byte("GET / HTTP/1.1\r\n\r\n")}}}
	if _, err := archive.WriteRequests(t.TempDir()); err == nil {
		t.Fatal("expected unsafe request name to be rejected")
	}
}
