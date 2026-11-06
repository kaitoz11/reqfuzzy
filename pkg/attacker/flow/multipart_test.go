package flow_test

import (
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"testing"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
)

func multipartRequest(t *testing.T) attacker.Request {
	t.Helper()
	body := []byte("preamble\r\n--CapturedBoundary \t\r\nContent-Disposition: form-data; name=\"token\"\r\nX-Custom: preserve  spaces\r\n\r\nold-token\r\n--CapturedBoundary\r\ncontent-disposition: form-data; name=\"upload\"; filename=\"../old.bin\"\r\nContent-Type: application/octet-stream\r\nX-File:  untouched\r\n\r\n")
	body = append(body, []byte{0, 255, 'f', 'i', 'l', 'e'}...)
	body = append(body, []byte("\r\n--CapturedBoundary--\r\nepilogue")...)
	raw := append([]byte("POST /upload HTTP/1.1\r\nContent-Type: multipart/form-data; boundary=CapturedBoundary\r\n\r\n"), body...)
	request, err := attacker.NewHClient().ParseRawRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func multipartParts(t *testing.T, request attacker.Request) (map[string][]byte, map[string]string) {
	t.Helper()
	_, params, err := mime.ParseMediaType(request.Headers.Get("Content-Type"))
	if err != nil {
		t.Fatal(err)
	}
	reader := multipart.NewReader(bytes.NewReader(request.Body), params["boundary"])
	values := map[string][]byte{}
	metadata := map[string]string{}
	for {
		part, err := reader.NextRawPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(part)
		if err != nil {
			t.Fatal(err)
		}
		_, disposition, err := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
		if err != nil {
			t.Fatal(err)
		}
		values[disposition["name"]] = data
		if disposition["name"] == "upload" {
			metadata["filename"] = disposition["filename"]
			metadata["type"] = part.Header.Get("Content-Type")
		}
	}
	return values, metadata
}

func TestMultipartMutationsPreserveUntouchedPartsAndBinaryValues(t *testing.T) {
	for _, tc := range []struct{ location, action, path, value string }{
		{"multipart", "set", "token", `"fresh-token"`},
		{"multipart", "append", "token", `"-tail"`},
		{"multipart", "remove", "token", ""},
		{"multipart-filename", "set", "upload", `"../new.txt"`},
		{"multipart-content-type", "set", "upload", `"image/custom"`},
		{"multipart-file", "append", "upload", `"Af4="`},
		{"multipart-file", "prepend", "upload", `"Af4="`},
	} {
		t.Run(tc.location+tc.action, func(t *testing.T) {
			request := multipartRequest(t)
			before := append([]byte(nil), request.Body...)
			mutation, err := flow.BuildMutation(flow.MutationSpec{Location: tc.location, Action: tc.action, Path: tc.path, Value: []byte(tc.value)})
			if err != nil {
				t.Fatal(err)
			}
			if err := mutation(request, nil); err != nil {
				t.Fatal(err)
			}
			values, meta := multipartParts(t, request)
			if !bytes.HasPrefix(request.Body, []byte("preamble\r\n")) || !bytes.HasSuffix(request.Body, []byte("epilogue")) {
				t.Fatal("multipart envelope changed")
			}
			if tc.location == "multipart" {
				file := before[bytes.Index(before, []byte("--CapturedBoundary\r\ncontent-disposition")):]
				if !bytes.Contains(request.Body, file) {
					t.Fatal("untouched file bytes/headers changed")
				}
				if tc.action == "set" && string(values["token"]) != "fresh-token" {
					t.Fatal("text not set")
				}
				if tc.action == "append" && string(values["token"]) != "old-token-tail" {
					t.Fatal("text not appended")
				}
				if tc.action == "remove" {
					if _, ok := values["token"]; ok {
						t.Fatal("text not removed")
					}
				}
			} else {
				if string(values["token"]) != "old-token" {
					t.Fatal("unrelated text changed")
				}
				if tc.location == "multipart-filename" && meta["filename"] != "../new.txt" {
					t.Fatal("filename was stripped or not changed")
				}
				if tc.location == "multipart-content-type" && meta["type"] != "image/custom" {
					t.Fatal("part type not changed")
				}
				if tc.location == "multipart-file" {
					want := []byte{0, 255, 'f', 'i', 'l', 'e'}
					if tc.action == "append" {
						want = append(want, 1, 254)
					} else {
						want = append([]byte{1, 254}, want...)
					}
					if !bytes.Equal(values["upload"], want) {
						t.Fatal("file bytes were not combined")
					}
				}
			}
		})
	}
}

func TestMultipartBoundaryCollisionIsReframedBeforeSend(t *testing.T) {
	request := multipartRequest(t)
	payload := []byte("prefix\r\n--CapturedBoundary\r\nnot another part")
	raw, err := flow.ParseValue([]byte(`"` + base64.StdEncoding.EncodeToString(payload) + `"`))
	if err != nil {
		t.Fatal(err)
	}
	mutation, err := flow.SetMutation("multipart-file", "upload", raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := mutation(request, nil); err != nil {
		t.Fatal(err)
	}
	_, params, _ := mime.ParseMediaType(request.Headers.Get("Content-Type"))
	if params["boundary"] == "CapturedBoundary" {
		t.Fatal("boundary collision was not resolved")
	}
	values, _ := multipartParts(t, request)
	if !bytes.Equal(values["upload"], payload) || string(values["token"]) != "old-token" {
		t.Fatal("reframing lost payload or other parts")
	}
}
