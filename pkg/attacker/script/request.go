package script

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/dop251/goja"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/rawreq"
	"github.com/tidwall/gjson"
	"golang.org/x/net/http/httpguts"
)

func requestObject(vm *goja.Runtime, request attacker.Request) (*goja.Object, http.Header, error) {
	parsed, err := url.Parse(request.RawURL)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid request URL")
	}
	if extra := request.QueryParams.Encode(); extra != "" {
		if parsed.RawQuery != "" {
			parsed.RawQuery += "&"
		}
		parsed.RawQuery += extra
	}
	headers := request.Headers.Clone()
	if headers == nil {
		headers = make(http.Header)
	}
	object := vm.NewObject()
	_ = object.Set("method", request.Method)
	_ = object.Set("url", parsed.String())
	_ = object.Set("body", string(request.Body))
	_ = object.Set("getHeader", func(name string) string {
		for key, values := range headers {
			if strings.EqualFold(key, name) && len(values) > 0 {
				return values[0]
			}
		}
		return ""
	})
	remove := func(name string) {
		for key := range headers {
			if strings.EqualFold(key, name) {
				delete(headers, key)
			}
		}
	}
	_ = object.Set("removeHeader", remove)
	_ = object.Set("setHeader", func(name, value string) error {
		if !httpguts.ValidHeaderFieldName(name) || !httpguts.ValidHeaderFieldValue(value) {
			return fmt.Errorf("invalid request header")
		}
		remove(name)
		headers[name] = []string{value}
		return nil
	})
	return object, headers, nil
}

func applyRequest(object *goja.Object, headers http.Header, request attacker.Request) error {
	method, err := stringProperty(object, "method")
	if err != nil || !httpguts.ValidHeaderFieldName(method) {
		return fmt.Errorf("request method must be an HTTP token")
	}
	rawURL, err := stringProperty(object, "url")
	if err != nil {
		return fmt.Errorf("request url must be a relative path")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.Fragment != "" || !strings.HasPrefix(rawURL, "/") || strings.HasPrefix(rawURL, "//") {
		return fmt.Errorf("request url must be a relative path without fragment")
	}
	body, err := stringProperty(object, "body")
	if err != nil {
		return fmt.Errorf("request body must be a string")
	}
	request.Method = method
	request.QueryParams = nil
	request.SetURL(rawURL)
	request.SetBodyBytes([]byte(body))
	request.Headers = headers
	bodyType := rawreq.None
	if gjson.Valid(body) {
		bodyType = rawreq.Json
	}
	request.SetContextData(rawreq.RequestBodyType, bodyType)
	return nil
}

func stringProperty(object *goja.Object, name string) (string, error) {
	value := object.Get(name)
	if value == nil || goja.IsUndefined(value) || goja.IsNull(value) {
		return "", fmt.Errorf("request %s must be a string", name)
	}
	if _, isObject := value.(*goja.Object); isObject {
		return "", fmt.Errorf("request %s must be a string", name)
	}
	text, ok := value.Export().(string)
	if !ok {
		return "", fmt.Errorf("request %s must be a string", name)
	}
	return text, nil
}
