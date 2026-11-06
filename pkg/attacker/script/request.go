package script

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

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
	if utf8.Valid(request.Body) {
		_ = object.Set("body", string(request.Body))
	} else {
		_ = object.Set("body", goja.Null())
	}
	_ = object.Set("bodyBase64", base64.StdEncoding.EncodeToString(request.Body))
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
	body, err := requestBody(object, request.Body)
	if err != nil {
		return err
	}
	request.Method = method
	request.QueryParams = nil
	request.SetURL(rawURL)
	request.SetBodyBytes(body)
	request.Headers = headers
	bodyType := rawreq.None
	if gjson.ValidBytes(body) {
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

// Both representations describe the original bytes. A script may change either,
// but simultaneous edits must agree. Validate before committing any request edits.
func requestBody(object *goja.Object, original []byte) ([]byte, error) {
	encoded, err := stringProperty(object, "bodyBase64")
	if err != nil {
		return nil, err
	}
	decoded, err := decodeBytes(encoded)
	if err != nil {
		return nil, err
	}
	value := object.Get("body")
	var textBytes []byte
	textChanged := false
	if value != nil && goja.IsNull(value) && !utf8.Valid(original) {
		// Null is only the unchanged binary text representation.
	} else {
		text, err := stringProperty(object, "body")
		if err != nil {
			return nil, err
		}
		textBytes = []byte(text)
		textChanged = !utf8.Valid(original) || !bytes.Equal(textBytes, original)
	}
	bytesChanged := !bytes.Equal(decoded, original)
	if textChanged && bytesChanged && !bytes.Equal(textBytes, decoded) {
		return nil, fmt.Errorf("request body and bodyBase64 edits conflict")
	}
	if textChanged {
		return textBytes, nil
	}
	if bytesChanged {
		return decoded, nil
	}
	return original, nil
}
