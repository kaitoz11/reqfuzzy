package capture

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type Exchange struct {
	Name                string
	Method              string
	URL                 string
	RequestRaw          []byte
	ResponseStatus      int
	ResponseBody        []byte
	ResponseBodyPresent bool
}

type Capture struct {
	Exchanges []Exchange
}

type harFile struct {
	Log struct {
		Version string     `json:"version"`
		Entries []harEntry `json:"entries"`
	} `json:"log"`
}

type harEntry struct {
	Request  harRequest   `json:"request"`
	Response *harResponse `json:"response"`
}

type harRequest struct {
	Method      string         `json:"method"`
	URL         string         `json:"url"`
	HTTPVersion string         `json:"httpVersion"`
	Headers     []harNameValue `json:"headers"`
	PostData    *harPostData   `json:"postData"`
}

type harNameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type harPostData struct {
	MIMEType string         `json:"mimeType"`
	Text     *string        `json:"text"`
	Params   []harNameValue `json:"params"`
}

type harResponse struct {
	Status  int `json:"status"`
	Content struct {
		Text     *string `json:"text"`
		Encoding string  `json:"encoding"`
		MIMEType string  `json:"mimeType"`
	} `json:"content"`
}

func ParseHAR(data []byte) (Capture, error) {
	data = bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})
	var archive harFile
	if err := json.Unmarshal(data, &archive); err != nil {
		return Capture{}, fmt.Errorf("decode HAR: %w", err)
	}
	if archive.Log.Version != "1.2" {
		return Capture{}, fmt.Errorf("unsupported HAR version %q", archive.Log.Version)
	}
	if len(archive.Log.Entries) == 0 {
		return Capture{}, fmt.Errorf("HAR has no entries")
	}
	result := Capture{Exchanges: make([]Exchange, 0, len(archive.Log.Entries))}
	for index, entry := range archive.Log.Entries {
		name, raw, err := materializeRequest(index, entry.Request)
		if err != nil {
			return Capture{}, fmt.Errorf("HAR entry %d: %w", index+1, err)
		}
		exchange := Exchange{Name: name, Method: entry.Request.Method, URL: entry.Request.URL, RequestRaw: raw}
		if entry.Response != nil {
			exchange.ResponseStatus = entry.Response.Status
			if text := entry.Response.Content.Text; text != nil {
				switch entry.Response.Content.Encoding {
				case "":
					exchange.ResponseBody = []byte(*text)
				case "base64":
					exchange.ResponseBody, err = base64.StdEncoding.DecodeString(*text)
					if err != nil {
						return Capture{}, fmt.Errorf("HAR entry %d: decode base64 response: %w", index+1, err)
					}
				default:
					return Capture{}, fmt.Errorf("HAR entry %d: unsupported response encoding %q", index+1, entry.Response.Content.Encoding)
				}
				exchange.ResponseBodyPresent = true
			}
		}
		result.Exchanges = append(result.Exchanges, exchange)
	}
	return result, nil
}
