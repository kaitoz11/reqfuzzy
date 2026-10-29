package attacker

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker/cookiefield"
)

type cookieEditsKey struct{}

func cookieEdits(request Request) map[string]bool {
	names, _ := request.Context().Value(cookieEditsKey{}).(map[string]bool)
	return names
}

func (r Request) markCookieEdit(name string) {
	names := make(map[string]bool)
	for key := range cookieEdits(r) {
		names[key] = true
	}
	names[name] = true
	r.SetContext(context.WithValue(r.Context(), cookieEditsKey{}, names))
}

func effectiveCookieHeaders(r Request) http.Header {
	headers := r.Headers.Clone()
	if headers == nil {
		headers = make(http.Header)
	}
	// The first edit materializes common Cookie headers into the request.
	if len(cookieEdits(r)) == 0 {
		for name, values := range r.GetClient().Headers {
			if strings.EqualFold(name, "Cookie") && len(headers[name]) == 0 {
				headers[name] = append([]string(nil), values...)
			}
		}
	}
	return headers
}

// CookieValues includes explicit cookies, client cookies, and the live jar for
// this request URL. A previously edited name hides its original automatic values.
func (r Request) CookieValues(name string) ([]string, error) {
	cookies, err := cookiefield.Parse(effectiveCookieHeaders(r))
	if err != nil {
		return nil, err
	}
	var values []string
	for _, cookie := range cookies {
		if cookie.Name == name {
			values = append(values, cookie.Value)
		}
	}
	if cookieEdits(r)[name] {
		return values, nil
	}
	client := r.GetClient()
	automatic := append([]*http.Cookie(nil), r.Cookies...)
	automatic = append(automatic, client.Cookies...)
	if jar := client.GetClient().Jar; jar != nil {
		parsed, err := url.Parse(r.RawURL)
		if err == nil && !parsed.IsAbs() {
			parsed, err = url.Parse(client.BaseURL + r.RawURL)
		}
		if err != nil {
			return nil, fmt.Errorf("invalid cookie target URL")
		}
		if cookieJarUsesRequestHost {
			host := r.Headers.Get("Host")
			if len(r.Headers["Host"]) == 0 {
				host = client.Headers.Get("Host")
			}
			if host != "" {
				parsed.Host = host
			}
		}
		automatic = append(automatic, jar.Cookies(parsed)...)
	}
	for _, cookie := range automatic {
		if cookie != nil && cookie.Name == name {
			if err := cookiefield.Valid(cookie.Name, cookie.Value); err != nil {
				return nil, err
			}
			values = append(values, cookie.Value)
		}
	}
	return values, nil
}

func (r Request) SetCookieValue(name, value string) error {
	headers, err := cookiefield.Edit(effectiveCookieHeaders(r), name, &value)
	if err != nil {
		return err
	}
	r.Headers = headers
	r.markCookieEdit(name)
	return nil
}

func (r Request) RemoveCookieValue(name string) error {
	headers, err := cookiefield.Edit(effectiveCookieHeaders(r), name, nil)
	if err != nil {
		return err
	}
	r.Headers = headers
	r.markCookieEdit(name)
	return nil
}

type editedCookieJar struct {
	base  http.CookieJar
	names map[string]bool
}

func withoutCookies(cookies []*http.Cookie, names map[string]bool) []*http.Cookie {
	var kept []*http.Cookie
	for _, cookie := range cookies {
		if cookie == nil || !names[cookie.Name] {
			kept = append(kept, cookie)
		}
	}
	return kept
}

func (j editedCookieJar) Cookies(target *url.URL) []*http.Cookie {
	if j.base == nil {
		return nil
	}
	return withoutCookies(j.base.Cookies(target), j.names)
}
func (j editedCookieJar) SetCookies(target *url.URL, cookies []*http.Cookie) {
	if j.base != nil {
		j.base.SetCookies(target, cookies)
	}
}

// Use a request-local client/jar adapter. The shared jar receives response
// updates normally; selected cookie overrides never become stored session state.
func withCookieEdits(request Request) func() {
	names := cookieEdits(request)
	if len(names) == 0 {
		return func() {}
	}
	original := request.GetClient()
	client := original.Clone()
	// Clone starts a dumper worker for its unused transport. Reuse the original
	// dump/HTTP transport while retaining cloned request defaults and headers.
	if client.Dump != nil && client.Dump != original.Dump {
		client.Dump.Stop()
		client.Dump = original.Dump
	}
	client.GetClient().Transport = original.GetClient().Transport
	client.Headers = original.Headers.Clone()
	for name := range client.Headers {
		if strings.EqualFold(name, "Cookie") {
			delete(client.Headers, name)
		}
	}
	client.SetCookieJar(editedCookieJar{original.GetClient().Jar, names})
	client.Cookies = withoutCookies(original.Cookies, names)
	previous := request.Cookies
	request.Cookies = withoutCookies(previous, names)
	request.SetClient(client)
	return func() { request.SetClient(original); request.Cookies = previous }
}
