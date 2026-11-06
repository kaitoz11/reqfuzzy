package multipartbody_test

import (
	"bytes"
	"encoding/base64"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/multipartbody"
	"net/http"
	"strings"
	"testing"
)

func fixture(headers, data string) (http.Header, []byte) {
	return http.Header{"Content-Type": {"multipart/form-data; boundary=B"}}, []byte("--B\r\n" + headers + "\r\n\r\n" + data + "\r\n--B--\r\n")
}
func TestMultipartRejectsAmbiguityEncodingAndInvalidEditsAtomically(t *testing.T) {
	for _, tc := range []struct{ name, headers, data, location, path, action, value string }{
		{"duplicate disposition", "Content-Disposition: form-data; name=x\r\nContent-Disposition: form-data; name=y", "a", "multipart", "x", "set", "b"},
		{"encoded content", "Content-Disposition: form-data; name=x\r\nContent-Transfer-Encoding: base64", "YQ==", "multipart", "x", "set", "b"},
		{"7bit edit", "Content-Disposition: form-data; name=x\r\nContent-Transfer-Encoding: 7bit", "a", "multipart", "x", "set", "☃"},
		{"bad binary", "Content-Disposition: form-data; name=x; filename=a", "a", "multipart-file", "x", "set", "?"},
		{"text is file", "Content-Disposition: form-data; name=x; filename=a", "a", "multipart", "x", "set", "b"},
		{"file is text", "Content-Disposition: form-data; name=x", "a", "multipart-file", "x", "set", "Yg=="},
		{"metadata injection", "Content-Disposition: form-data; name=x; filename=a", "a", "multipart-filename", "x", "set", "a\r\nX: b"},
		{"missing ordinal", "Content-Disposition: form-data; name=x", "a", "multipart", "index:2", "set", "b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, b := fixture(tc.headers, tc.data)
			before := append([]byte(nil), b...)
			if _, _, err := multipartbody.Edit(h, b, tc.location, tc.path, tc.action, tc.value); err == nil {
				t.Fatal("invalid edit accepted")
			}
			if !bytes.Equal(before, b) || h.Get("Content-Type") != "multipart/form-data; boundary=B" {
				t.Fatal("error mutated inputs")
			}
		})
	}
}
func TestMultipartOrdinalsAndEscapedNames(t *testing.T) {
	h, b := fixture("Content-Disposition: form-data; name=x", "first")
	b = bytes.Replace(b, []byte("--B--"), []byte("--B\r\nContent-Disposition: form-data; name=x\r\n\r\nsecond\r\n--B--"), 1)
	if _, _, err := multipartbody.Edit(h, b, "multipart", "x", "set", "changed"); err == nil {
		t.Fatal("ambiguous name accepted")
	}
	h, b, err := multipartbody.Edit(h, b, "multipart", "index:1", "set", "changed")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := multipartbody.Parse(h, b)
	if err != nil || len(doc.Parts) != 2 || string(doc.Parts[0].Data) != "first" || string(doc.Parts[1].Data) != "changed" {
		t.Fatalf("ordinal edit err=%v", err)
	}
	h, b, err = multipartbody.Edit(h, b, "multipart", "index:0", "remove", "")
	if err != nil {
		t.Fatal(err)
	}
	doc, _ = multipartbody.Parse(h, b)
	if len(doc.Parts) != 1 || string(doc.Parts[0].Data) != "changed" {
		t.Fatal("ordinal delete")
	}
	h, b = fixture("Content-Disposition: form-data; name=\"index:0\"", "first")
	h, b, err = multipartbody.Edit(h, b, "multipart", "name:index:0", "set", "escaped")
	if err != nil {
		t.Fatal(err)
	}
	value, found, err := multipartbody.Value(h, b, "multipart", "name:index:0")
	if err != nil || !found || string(value) != "escaped" {
		t.Fatal("escaped name lost")
	}
	for _, address := range []string{"index:-1", "index:01", "index:1000", "name:", "x\nY"} {
		if _, _, err := multipartbody.Address(address); err == nil {
			t.Fatalf("invalid address %q", address)
		}
	}
}
func TestMultipartCreatesFilePlaceholderAndRemovesMetadata(t *testing.T) {
	h, b := fixture("X-Other: keep", "data")
	var err error
	h, b, err = multipartbody.Edit(h, b, "multipart-filename", "index:0", "set", "../file.bin")
	if err != nil {
		t.Fatal(err)
	}
	h, b, err = multipartbody.Edit(h, b, "multipart-file", "index:0", "set", base64.StdEncoding.EncodeToString([]byte{0, 255}))
	if err != nil {
		t.Fatal(err)
	}
	h, b, err = multipartbody.Edit(h, b, "multipart-filename", "index:0", "remove", "")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := multipartbody.Parse(h, b)
	if err != nil || doc.Parts[0].File || !bytes.Equal(doc.Parts[0].Data, []byte{0, 255}) || doc.Parts[0].Headers.Get("X-Other") != "keep" {
		t.Fatal("metadata removal lost content")
	}
	h, b, err = multipartbody.Edit(h, b, "multipart-filename", "new", "set", "new.bin")
	if err != nil {
		t.Fatal(err)
	}
	h, b, err = multipartbody.Edit(h, b, "multipart-content-type", "new", "remove", "")
	if err != nil {
		t.Fatal(err)
	}
	doc, _ = multipartbody.Parse(h, b)
	if len(doc.Parts) != 2 || doc.Parts[1].Filename != "new.bin" || len(doc.Parts[1].Data) != 0 || doc.Parts[1].Headers.Get("Content-Type") != "" {
		t.Fatal("file placeholder")
	}
}
func TestMultipartFramingAndBounds(t *testing.T) {
	h, b := fixture("Content-Disposition: form-data; name=x", "data")
	for _, bad := range [][]byte{bytes.TrimSuffix(b, []byte("--B--\r\n")), []byte("--B\r\nno headers\r\n--B--\r\n"), bytes.Repeat([]byte("x"), multipartbody.MaxBodyBytes+1), []byte("--B\r\nX: " + strings.Repeat("a", 64<<10) + "\r\n\r\nx\r\n--B--")} {
		if _, err := multipartbody.Parse(h, bad); err == nil {
			t.Fatal("malformed or oversized body accepted")
		}
	}
	h.Set("Content-Encoding", "gzip")
	if _, err := multipartbody.Parse(h, b); err == nil {
		t.Fatal("encoded body accepted")
	}
	h.Del("Content-Encoding")
	h.Add("Content-Type", "multipart/form-data; boundary=B")
	if _, err := multipartbody.Parse(h, b); err == nil {
		t.Fatal("ambiguous outer type accepted")
	}
}

func TestNamedSelectionRequiresFormDataDisposition(t *testing.T) {
	h, b := fixture("Content-Disposition: attachment; name=x; filename=a.bin", "data")
	doc, err := multipartbody.Parse(h, b)
	if err != nil {
		t.Fatal(err)
	}
	if value, found, err := doc.Value("multipart-file", "x"); err != nil || found {
		t.Fatalf("attachment is not a named form field: value=%q found=%v err=%v", value, found, err)
	}
	if value, found, err := doc.Value("multipart-file", "index:0"); err != nil || !found || string(value) != "data" {
		t.Fatal("explicit raw ordinal must remain usable")
	}
}
