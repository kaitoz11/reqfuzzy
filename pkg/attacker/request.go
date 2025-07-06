package attacker

import (
	"bufio"
	"errors"
	"fmt"
	"strings"

	"github.com/imroc/req/v3"
)

type Request struct {
	*req.Request
}

func ParseRawRequest(client *req.Client, rawRequest string) (*req.Request, error) {
	request := client.R()

	// Split the raw request into lines
	scanner := bufio.NewScanner(strings.NewReader(rawRequest))

	// Read the request line (first line)
	if !scanner.Scan() {
		return nil, errors.New("invalid raw request: invalid request line found")
	}

	requestLine := scanner.Text()
	fmt.Println("Request Line:", requestLine)

	// Parse the request line
	method, url, _, err := parseRequestLine(requestLine)
	if err != nil {
		return nil, fmt.Errorf("invalid raw request: %w", err)
	}

	request.Method = method
	request.SetURL(url)
	// Set the protocol (HTTP/1.1, HTTP/2, etc.) if needed

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
		request.SetHeaderNonCanonical(key, value)
	}

	// Parse the body if present
	if scanner.Scan() {
		body := scanner.Text()
		if body != "" {
			// Set the body of the request
			request.SetBodyString(body)
		}
	}

	return request, nil
}

func parseRequestLine(requestLine string) (string, string, string, error) {
	parts := strings.Split(requestLine, " ")
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("invalid request line format [%s]", requestLine)
	}

	method := parts[0]
	url := parts[1]
	protocol := parts[2]

	return method, url, protocol, nil
}

func parseHeaderLine(headerLine string) (key, value string, err error) {
	parts := strings.SplitN(headerLine, ": ", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid header format [%s]", headerLine)
	}
	return parts[0], parts[1], nil
}
