package rawreq_test

import (
	"bytes"
	"testing"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker/rawreq"
)

func TestParseMultilineBody(t *testing.T) {
	t.Run("multiline JSON", func(t *testing.T) {
		body := []byte("{\n  \"name\": \"a\"\n}\n")
		raw := append([]byte("POST /items HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\n\r\n"), body...)
		parsed, err := rawreq.ParseRawRequest(raw)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(parsed.Body, body) {
			t.Fatalf("body = %q, want %q", parsed.Body, body)
		}
		if parsed.BodyType != rawreq.Json {
			t.Fatalf("body type = %v, want JSON", parsed.BodyType)
		}
	})

	t.Run("binary body", func(t *testing.T) {
		body := []byte{0, 10, 255}
		raw := append([]byte("POST /upload HTTP/1.1\nHost: example.test\n\n"), body...)
		parsed, err := rawreq.ParseRawRequest(raw)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(parsed.Body, body) {
			t.Fatalf("body = %v, want %v", parsed.Body, body)
		}
	})

	t.Run("LF headers with CRLF separator bytes in body", func(t *testing.T) {
		body := []byte{0, '\r', '\n', '\r', '\n', 255}
		raw := append([]byte("POST /upload HTTP/1.1\nHost: example.test\n\n"), body...)
		parsed, err := rawreq.ParseRawRequest(raw)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(parsed.Body, body) {
			t.Fatalf("body = %v, want %v", parsed.Body, body)
		}
	})
}

func TestParseRawRequest(t *testing.T) {
	t.Run("Parse raw request", normalRequestParse)
	t.Run("Parse raw request with options", normalRequestParseWithOptions)
}

func normalRequestParseWithOptions(t *testing.T) {
	// Arrange
	rawRequest := []byte(`GET /api/v1/users HTTP/1.1
Host: example.com
User-Agent: Go-http-client/1.1
Content-Length: 14
Content-Type: application/json
Accept-Encoding: gzip
Tl-Tool: reqfuzzy
Tl-Tool: reqfuzzy
Tl-Tool: reqfuzzy

{"id":1,"name":"kaito"}`)

	options := rawreq.NewOptions()
	options.BlacklistedHeaders.Add("Tl-Tool")

	// Act
	parsedRequest, err := rawreq.ParseRawRequest(rawRequest, options)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(parsedRequest)

	// Assert
	if parsedRequest.Method != "GET" {
		t.Errorf("Method = %s, want GET", parsedRequest.Method)
	}
	if parsedRequest.Path != "/api/v1/users" {
		t.Errorf("Path = %s, want /api/v1/users", parsedRequest.Path)
	}
	if len(parsedRequest.Headers) != 5 {
		t.Errorf("len(Headers) = %d, want 5", len(parsedRequest.Headers))
	}

	for _, header := range parsedRequest.Headers {
		if header.Key == "Tl-Tool" {
			t.Errorf("Header Tl-Tool = %s, want not to be in the list", header.Value)
		}
	}
}

func normalRequestParse(t *testing.T) {
	// Arrange
	rawRequest := []byte(`GET /api/v1/users HTTP/1.1
Host: example.com
User-Agent: Go-http-client/1.1
Content-Length: 14
Content-Type: application/json
Accept-Encoding: gzip
Tl-Tool: reqfuzzy

{"id":1,"name":"kaito"}`)

	// Act
	parsedRequest, err := rawreq.ParseRawRequest(rawRequest)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(parsedRequest)

	// Assert
	if parsedRequest.Method != "GET" {
		t.Errorf("Method = %s, want GET", parsedRequest.Method)
	}
	if parsedRequest.Path != "/api/v1/users" {
		t.Errorf("Path = %s, want /api/v1/users", parsedRequest.Path)
	}
	if len(parsedRequest.Headers) != 6 {
		t.Errorf("len(Headers) = %d, want 6", len(parsedRequest.Headers))
	}
}
