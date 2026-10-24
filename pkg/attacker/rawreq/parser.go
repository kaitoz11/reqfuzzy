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

type Options struct {
	BlacklistedHeaders             HeaderKeySet
	BlacklistedHeaderCaseSensitive bool
}

type HeaderKeySet map[string]struct{}

func (h HeaderKeySet) Add(key string) {
	h[key] = struct{}{}
}

func (h HeaderKeySet) Contains(key string) bool {
	_, ok := h[key]
	return ok
}

func (h HeaderKeySet) Append(headerKeySet HeaderKeySet) {
	for k := range headerKeySet {
		h.Add(k)
	}
}
func (h HeaderKeySet) ContainsFold(key string) bool {
	for k := range h {
		if strings.EqualFold(k, key) {
			return true
		}
	}

	return false
}

func (h HeaderKeySet) Remove(key string) {
	delete(h, key)
}

func (h HeaderKeySet) IsEmpty() bool {
	return len(h) == 0
}

func NewOptions() Options {
	return useOptions()
}

func useOptions(opts ...Options) Options {
	option := Options{
		BlacklistedHeaders:             make(HeaderKeySet),
		BlacklistedHeaderCaseSensitive: false,
	}
	for _, opt := range opts {
		option.BlacklistedHeaders.Append(opt.BlacklistedHeaders)
		option.BlacklistedHeaderCaseSensitive = opt.BlacklistedHeaderCaseSensitive
	}
	return option
}

func headerKeyIsBlacklisted(key string, opts Options) bool {

	if opts.BlacklistedHeaderCaseSensitive {
		return opts.BlacklistedHeaders.ContainsFold(key)
	}

	return opts.BlacklistedHeaders.Contains(key)
}

func ParseRawRequest(rawRequest []byte, opts ...Options) (*ParsedRawRequest, error) {
	opt := useOptions(opts...)
	headerBytes := rawRequest
	var bodyBytes []byte
	crlfSeparator := bytes.Index(rawRequest, []byte("\r\n\r\n"))
	lfSeparator := bytes.Index(rawRequest, []byte("\n\n"))
	if crlfSeparator >= 0 && (lfSeparator < 0 || crlfSeparator < lfSeparator) {
		headerBytes = rawRequest[:crlfSeparator]
		bodyBytes = rawRequest[crlfSeparator+4:]
	} else if lfSeparator >= 0 {
		headerBytes = rawRequest[:lfSeparator]
		bodyBytes = rawRequest[lfSeparator+2:]
	}

	scanner := bufio.NewScanner(bytes.NewReader(headerBytes))

	if len(headerBytes) > bufio.MaxScanTokenSize {
		scanner.Buffer(make([]byte, 0, len(headerBytes)), len(headerBytes)+1)
	}

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

		if headerKeyIsBlacklisted(key, opt) {
			// Skip the header if it is blacklisted
			continue
		}

		headers = append(headers, ParsedHeader{
			Key:   key,
			Value: value,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("invalid raw request: %w", err)
	}

	fullBodyBytes := bytes.Clone(bodyBytes)

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

func ParseRawRequestFromFile(filePath string, opts ...Options) (*ParsedRawRequest, error) {
	rawRequest, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	return ParseRawRequest(rawRequest, opts...)
}
