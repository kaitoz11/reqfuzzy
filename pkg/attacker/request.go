package attacker

import (
	"fmt"

	"github.com/imroc/req/v3"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/rawreq"
	"github.com/tidwall/sjson"
)

type Request struct {
	*req.Request
}

func (r *Request) UpdateJsonBody(key string, value any) (err error) {
	if r.GetContextData(rawreq.RequestBodyType).(rawreq.BodyType) != rawreq.Json {
		return fmt.Errorf("request body is not json")
	}

	updatedJsonBody, err := sjson.SetBytes(r.Body, key, value)
	if err != nil {
		return
	}

	r.SetBodyBytes(updatedJsonBody)
	return
}

func (r *Request) DeleteJsonData(key string, value any) (err error) {
	if r.GetContextData(rawreq.RequestBodyType).(rawreq.BodyType) != rawreq.Json {
		return fmt.Errorf("request body is not json")
	}

	updatedJsonBody, err := sjson.DeleteBytes(r.Body, key)
	if err != nil {
		return
	}

	r.SetBodyBytes(updatedJsonBody)
	return
}

func FromParsedRawRequestAdapter(client *req.Client, parsedRawRequest *rawreq.ParsedRawRequest) (*req.Request, error) {
	request := client.R()

	request.Method = parsedRawRequest.Method
	request.SetURL(parsedRawRequest.Path)
	// Set the protocol (HTTP/1.1, HTTP/2, etc.) if needed

	headerOrder := make([]string, 0, len(parsedRawRequest.Headers))

	for _, header := range parsedRawRequest.Headers {
		headerOrder = append(headerOrder, header.Key)
		request.SetHeaderNonCanonical(header.Key, header.Value)
	}
	request.SetHeaderOrder(headerOrder...)

	request.SetContextData(rawreq.RequestBodyType, parsedRawRequest.BodyType)

	request.SetBodyBytes(parsedRawRequest.Body)

	return request, nil
}
