package capture

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"
)

func materializeRequest(index int, request harRequest) (string, []byte, error) {
	if !validHTTPToken(request.Method) {
		return "", nil, fmt.Errorf("invalid request method %q", request.Method)
	}
	parsed, err := url.Parse(request.URL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.Fragment != "" || parsed.User != nil {
		return "", nil, fmt.Errorf("invalid absolute HTTP URL")
	}
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	target := path
	if parsed.RawQuery != "" {
		target += "?" + parsed.RawQuery
	}

	var body []byte
	if request.PostData != nil {
		if request.PostData.Text != nil {
			body = []byte(*request.PostData.Text)
		} else if len(request.PostData.Params) > 0 {
			if !strings.EqualFold(strings.TrimSpace(strings.SplitN(request.PostData.MIMEType, ";", 2)[0]), "application/x-www-form-urlencoded") {
				return "", nil, fmt.Errorf("params-only %q postData cannot be replayed", request.PostData.MIMEType)
			}
			parts := make([]string, 0, len(request.PostData.Params))
			for _, param := range request.PostData.Params {
				parts = append(parts, url.QueryEscape(param.Name)+"="+url.QueryEscape(param.Value))
			}
			body = []byte(strings.Join(parts, "&"))
		}
	}

	var raw bytes.Buffer
	fmt.Fprintf(&raw, "%s %s HTTP/1.1\r\n", request.Method, target)
	hasHost := false
	hasContentType := false
	for _, header := range request.Headers {
		if !validHeader(header) {
			return "", nil, fmt.Errorf("invalid header %q", header.Name)
		}
		if strings.EqualFold(header.Name, "Content-Length") || strings.EqualFold(header.Name, "Transfer-Encoding") {
			continue
		}
		hasHost = hasHost || strings.EqualFold(header.Name, "Host")
		hasContentType = hasContentType || strings.EqualFold(header.Name, "Content-Type")
		fmt.Fprintf(&raw, "%s: %s\r\n", header.Name, header.Value)
	}
	if !hasHost {
		fmt.Fprintf(&raw, "Host: %s\r\n", parsed.Host)
	}
	if request.PostData != nil && request.PostData.MIMEType != "" && !hasContentType {
		fmt.Fprintf(&raw, "Content-Type: %s\r\n", request.PostData.MIMEType)
	}
	raw.WriteString("\r\n")
	raw.Write(body)

	name := fmt.Sprintf("%04d_%s_%s", index+1, strings.ToLower(request.Method), pathSlug(path))
	return name, raw.Bytes(), nil
}

func validHeader(header harNameValue) bool {
	if !validHTTPToken(header.Name) {
		return false
	}
	for index := 0; index < len(header.Value); index++ {
		character := header.Value[index]
		if character != '\t' && (character < 0x20 || character == 0x7f) {
			return false
		}
	}
	return true
}

func validHTTPToken(token string) bool {
	if token == "" {
		return false
	}
	for index := 0; index < len(token); index++ {
		character := token[index]
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(character)) {
			continue
		}
		return false
	}
	return true
}

func pathSlug(path string) string {
	var slug strings.Builder
	lastSeparator := false
	for _, character := range strings.Trim(path, "/") {
		if slug.Len() >= 48 {
			break
		}
		if character >= 'A' && character <= 'Z' {
			character += 'a' - 'A'
		}
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
			slug.WriteRune(character)
			lastSeparator = false
		} else if !lastSeparator && slug.Len() > 0 {
			slug.WriteByte('_')
			lastSeparator = true
		}
	}
	result := strings.Trim(slug.String(), "_")
	if result == "" {
		return "root"
	}
	return result
}
