package flow

import (
	"encoding/base64"
	"fmt"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/multipartbody"
)

func applyMultipart(request attacker.Request, location, path, action, text string) error {
	headers, body, err := multipartbody.Edit(request.Headers, request.Body, location, path, action, text)
	if err != nil {
		return err
	}
	request.Headers = headers
	request.SetBodyBytes(body)
	return nil
}

func currentMultipart(request attacker.Request, location, path string) (Value, error) {
	data, exists, err := multipartbody.Value(request.Headers, request.Body, location, path)
	if err != nil {
		return Value{}, err
	}
	if !exists {
		return Value{}, fmt.Errorf("multipart value is absent")
	}
	text := string(data)
	if location == "multipart-file" {
		text = base64.StdEncoding.EncodeToString(data)
	}
	return Value{Text: text}, nil
}
