package capture_test

import (
	"fmt"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/capture"
	"testing"
)

func TestMultipartInferenceIncludesTextFileAndFullMetadata(t *testing.T) {
	for _, duplicate := range []bool{false, true} {
		body := "--B\r\nContent-Disposition: form-data; name=\"index:0\"\r\n\r\ncaptured-123\r\n--B\r\nContent-Disposition: form-data; name=file; filename=\"../captured.bin\"\r\nContent-Type: image/custom\r\n\r\nhello\r\n"
		if duplicate {
			body += "--B\r\nContent-Disposition: form-data; name=file; filename=other\r\n\r\nother\r\n"
		}
		body += "--B--\r\n"
		archive := capture.Capture{Exchanges: []capture.Exchange{
			{Name: "source", URL: "http://capture.test/source", RequestRaw: []byte("GET /source HTTP/1.1\r\n\r\n"), ResponseBodyPresent: true, ResponseBody: []byte(`{"csrf":"captured-123","filename":"../captured.bin","type":"image/custom","data":"aGVsbG8="}`)},
			{Name: "upload", URL: "http://capture.test/upload", RequestRaw: []byte("POST /upload HTTP/1.1\r\nContent-Type: multipart/form-data; boundary=B\r\n\r\n" + body)},
		}}
		suggestion, err := capture.SuggestFlow(archive)
		if err != nil {
			t.Fatal(err)
		}
		want := 4
		if duplicate {
			want = 1
		}
		if len(suggestion.Links) != want {
			t.Fatalf("duplicate=%v links=%+v", duplicate, suggestion.Links)
		}
		seen := map[string]bool{}
		for _, link := range suggestion.Links {
			seen[fmt.Sprintf("%s:%s", link.ToLocation, link.ToPath)] = true
		}
		if !seen["multipart:name:index:0"] {
			t.Fatal("escaped text address absent")
		}
		if !duplicate {
			for _, location := range []string{"multipart-file", "multipart-filename", "multipart-content-type"} {
				if !seen[location+":file"] {
					t.Fatalf("missing %s", location)
				}
			}
		}
	}
}
