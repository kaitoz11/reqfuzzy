// Package cookiefield reads and edits named request cookies without silently
// accepting malformed fields or treating case-sensitive names as headers.
package cookiefield

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
)

func Valid(name, value string) error {
	if err := (&http.Cookie{Name: name, Value: value}).Valid(); err != nil {
		return fmt.Errorf("invalid cookie name or value")
	}
	return nil
}

func Parse(headers http.Header) ([]*http.Cookie, error) {
	var keys []string
	for name := range headers {
		if strings.EqualFold(name, "Cookie") {
			keys = append(keys, name)
		}
	}
	sort.Strings(keys)
	var cookies []*http.Cookie
	for _, key := range keys {
		for _, line := range headers[key] {
			parsed, err := http.ParseCookie(line)
			if err != nil {
				return nil, fmt.Errorf("invalid Cookie header")
			}
			cookies = append(cookies, parsed...)
		}
	}
	return cookies, nil
}

func ResponseCookies(headers http.Header) ([]*http.Cookie, error) {
	var cookies []*http.Cookie
	for name, lines := range headers {
		if !strings.EqualFold(name, "Set-Cookie") {
			continue
		}
		for _, line := range lines {
			cookie, err := http.ParseSetCookie(line)
			if err != nil || cookie.Valid() != nil {
				return nil, fmt.Errorf("invalid Set-Cookie header")
			}
			cookies = append(cookies, cookie)
		}
	}
	return cookies, nil
}

// Edit replaces all selected-name occurrences, or removes them when value is
// nil. It returns a new header map only after complete validation succeeds.
func Edit(headers http.Header, name string, value *string) (http.Header, error) {
	text := ""
	if value != nil {
		text = *value
	}
	if err := Valid(name, text); err != nil {
		return nil, err
	}
	cookies, err := Parse(headers)
	if err != nil {
		return nil, err
	}
	parts := make([]string, 0, len(cookies)+1)
	replaced := false
	for _, cookie := range cookies {
		if cookie.Name != name {
			parts = append(parts, cookie.String())
			continue
		}
		if value != nil && !replaced {
			parts = append(parts, (&http.Cookie{Name: name, Value: *value}).String())
			replaced = true
		}
	}
	if value != nil && !replaced {
		parts = append(parts, (&http.Cookie{Name: name, Value: *value}).String())
	}
	result := headers.Clone()
	if result == nil {
		result = make(http.Header)
	}
	for key := range result {
		if strings.EqualFold(key, "Cookie") {
			delete(result, key)
		}
	}
	if len(parts) > 0 {
		result["Cookie"] = []string{strings.Join(parts, "; ")}
	}
	return result, nil
}
