package flow

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Path addresses count slash-delimited slots after the initial slash, starting
// at zero. Split the escaped path so an encoded slash remains part of one slot.
func pathIndex(address string) (int, error) {
	index, err := strconv.Atoi(address)
	if err != nil || index < 0 || strconv.Itoa(index) != address {
		return 0, fmt.Errorf("path binding needs a canonical nonnegative segment index")
	}
	return index, nil
}

func pathAddress(rawURL, address string) (*url.URL, []string, int, error) {
	index, err := pathIndex(address)
	if err != nil {
		return nil, nil, 0, err
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.User != nil || parsed.Fragment != "" || !strings.HasPrefix(rawURL, "/") || strings.HasPrefix(rawURL, "//") {
		return nil, nil, 0, fmt.Errorf("path binding requires a relative request path without a fragment")
	}
	parts := strings.Split(strings.TrimPrefix(parsed.EscapedPath(), "/"), "/")
	if index >= len(parts) {
		return nil, nil, 0, fmt.Errorf("path binding segment %d is outside the captured path", index)
	}
	return parsed, parts, index, nil
}

func replacePathSegment(rawURL, address, value string) (string, error) {
	parsed, parts, index, err := pathAddress(rawURL, address)
	if err != nil {
		return "", err
	}
	encoded := url.PathEscape(value)
	if value == "." || value == ".." {
		encoded = strings.ReplaceAll(value, ".", "%2E")
	}
	parts[index] = encoded
	return renderPath(parsed, parts)
}

func removePathSegment(rawURL, address string) (string, error) {
	parsed, parts, index, err := pathAddress(rawURL, address)
	if err != nil {
		return "", err
	}
	parts = append(parts[:index], parts[index+1:]...)
	if "/"+strings.Join(parts, "/") == parsed.EscapedPath() {
		return "", fmt.Errorf("path removal would not change the path")
	}
	return renderPath(parsed, parts)
}

func renderPath(parsed *url.URL, parts []string) (string, error) {
	updated := "/" + strings.Join(parts, "/")
	if strings.HasPrefix(updated, "//") {
		return "", fmt.Errorf("path binding would create a network-path reference")
	}
	if parsed.RawQuery != "" || parsed.ForceQuery {
		updated += "?" + parsed.RawQuery
	}
	return updated, nil
}
