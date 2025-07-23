package rawreq

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/tidwall/gjson"
)

type ParsedRawRequest struct {
	// RequestLine string
	Method   string
	Path     string
	Protocol string

	// Headers
	Headers []ParsedHeader

	// Body
	Body []byte

	BodyType BodyType
}

type ParsedHeader struct {
	Key   string
	Value string
}

func parseRequestLine(requestLine string) (string, string, string, error) {
	parts := strings.Split(requestLine, " ")
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("invalid request line format [%s]", requestLine)
	}

	method := parts[0]
	path := parts[1]
	protocol := parts[2]

	return method, path, protocol, nil
}

func parseHeaderLine(headerLine string) (key, value string, err error) {
	parts := strings.SplitN(headerLine, ": ", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid header format [%s]", headerLine)
	}
	return parts[0], parts[1], nil
}

func ParseRawRequest(rawRequest []byte) (*ParsedRawRequest, error) {
	// Split the raw request into lines
	scanner := bufio.NewScanner(bytes.NewReader(rawRequest))

	// Read the request line (first line)
	if !scanner.Scan() {
		return nil, errors.New("invalid raw request: invalid request line found")
	}

	requestLine := scanner.Text()

	// Parse the request line
	method, path, protocol, err := parseRequestLine(requestLine)
	if err != nil {
		return nil, fmt.Errorf("invalid raw request: %w", err)
	}

	// request.SetURL(url)
	// Set the protocol (HTTP/1.1, HTTP/2, etc.) if needed

	headers := make([]ParsedHeader, 0)
	// Parse the headers
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			// An empty line indicates the end of headers
			break
		}
		// Split the header line into key and value
		key, value, err := parseHeaderLine(line)
		if err != nil {
			return nil, fmt.Errorf("invalid raw request: %w", err)
		}
		headers = append(headers, ParsedHeader{
			Key:   key,
			Value: value,
		})
	}

	// Parse the body if present
	fullBodyBytes := make([]byte, 0)
	if scanner.Scan() {
		bodyBytes := scanner.Bytes()

		if len(bodyBytes) > 0 {
			// apped the body of the request
			fullBodyBytes = append(fullBodyBytes, bodyBytes...)
		}
	}

	reqBodyType := None

	if len(fullBodyBytes) != 0 {
		// Json body
		if gjson.ValidBytes(fullBodyBytes) {
			reqBodyType = Json
		}
	}

	return &ParsedRawRequest{
		Method:   method,
		Path:     path,
		Protocol: protocol,
		Headers:  headers,
		Body:     fullBodyBytes,
		BodyType: reqBodyType,
	}, nil
}

func ParseRawRequestFromFile(filePath string) (*ParsedRawRequest, error) {
	rawRequest, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	return ParseRawRequest(rawRequest)
}
