// Package urlform edits UTF-8 application/x-www-form-urlencoded bodies while
// preserving the bytes and ordering of fields outside the selected key.
package urlform

import (
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"
)

func contentType(headers http.Header) (string, map[string]string, error) {
	var values []string
	for key, parts := range headers {
		if strings.EqualFold(key, "Content-Type") {
			values = append(values, parts...)
		}
	}
	if len(values) != 1 {
		return "", nil, fmt.Errorf("form body requires one Content-Type")
	}
	media, params, err := mime.ParseMediaType(values[0])
	if err != nil {
		return "", nil, fmt.Errorf("invalid form Content-Type")
	}
	return media, params, nil
}

func IsForm(headers http.Header) bool {
	media, _, err := contentType(headers)
	return err == nil && media == "application/x-www-form-urlencoded"
}

func Parse(headers http.Header, body []byte) (url.Values, error) {
	for name, values := range headers {
		if strings.EqualFold(name, "Content-Encoding") {
			for _, value := range values {
				coding := strings.TrimSpace(value)
				if coding != "" && !strings.EqualFold(coding, "identity") {
					return nil, fmt.Errorf("form location does not support content encoding")
				}
			}
		}
	}
	media, params, err := contentType(headers)
	if err != nil || media != "application/x-www-form-urlencoded" {
		return nil, fmt.Errorf("form location requires application/x-www-form-urlencoded")
	}
	charset := strings.ToLower(params["charset"])
	if charset != "" && charset != "utf-8" && charset != "utf8" {
		return nil, fmt.Errorf("form location requires UTF-8 encoding")
	}
	fields, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, fmt.Errorf("invalid URL-encoded form")
	}
	for key, values := range fields {
		if !utf8.ValidString(key) {
			return nil, fmt.Errorf("invalid UTF-8 form key")
		}
		for _, value := range values {
			if !utf8.ValidString(value) {
				return nil, fmt.Errorf("invalid UTF-8 form value")
			}
		}
	}
	return fields, nil
}

func Set(headers http.Header, body []byte, key, value string) ([]byte, error) {
	if _, err := Parse(headers, body); err != nil {
		return nil, err
	}
	if !utf8.ValidString(key) || !utf8.ValidString(value) {
		return nil, fmt.Errorf("form replacement requires UTF-8 text")
	}
	return rewrite(body, key, &value), nil
}

func Remove(headers http.Header, body []byte, key string) ([]byte, error) {
	fields, err := Parse(headers, body)
	if err != nil {
		return nil, err
	}
	if _, exists := fields[key]; !exists {
		return nil, fmt.Errorf("mutation form key does not exist")
	}
	return rewrite(body, key, nil), nil
}

func rewrite(body []byte, key string, value *string) []byte {
	var parts []string
	if len(body) > 0 {
		parts = strings.Split(string(body), "&")
	}
	kept := make([]string, 0, len(parts)+1)
	replaced := false
	for _, part := range parts {
		rawKey, _, _ := strings.Cut(part, "=")
		decoded, _ := url.QueryUnescape(rawKey) // Parse validated every component.
		if decoded != key {
			kept = append(kept, part)
			continue
		}
		if value != nil && !replaced {
			kept = append(kept, rawKey+"="+url.QueryEscape(*value))
			replaced = true
		}
	}
	if value != nil && !replaced {
		kept = append(kept, url.QueryEscape(key)+"="+url.QueryEscape(*value))
	}
	return []byte(strings.Join(kept, "&"))
}
