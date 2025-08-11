package rawreq_test

import (
	"testing"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker/rawreq"
)

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
