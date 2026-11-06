// Package multipartbody edits captured multipart bodies without reserializing
// untouched part headers or binary content.
package multipartbody

import (
	"bufio"
	"bytes"
	"fmt"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
	"unicode/utf8"
)

const MaxBodyBytes = 16 << 20
const MaxParts = 1000

func Location(value string) bool {
	switch value {
	case "multipart", "multipart-file", "multipart-filename", "multipart-content-type":
		return true
	}
	return false
}

type Part struct {
	Name, Filename, Disposition string
	File                        bool
	Params                      map[string]string
	Headers                     http.Header
	RawHeader, Data, Tail       []byte
}
type Document struct {
	Boundary                      string
	Params                        map[string]string
	Preamble, Epilogue, CloseTail []byte
	Parts                         []Part
}
type delimiter struct {
	start, end int
	closing    bool
}

func contentType(headers http.Header) (string, map[string]string, error) {
	var values []string
	for key, parts := range headers {
		if strings.EqualFold(key, "Content-Type") {
			values = append(values, parts...)
		}
	}
	if len(values) != 1 {
		return "", nil, fmt.Errorf("multipart requires one Content-Type")
	}
	media, params, err := mime.ParseMediaType(values[0])
	if err != nil {
		return "", nil, fmt.Errorf("invalid multipart Content-Type")
	}
	return media, params, nil
}
func IsMultipart(headers http.Header) bool {
	media, _, err := contentType(headers)
	return err == nil && media == "multipart/form-data"
}
func identity(headers http.Header) error {
	for name, values := range headers {
		if strings.EqualFold(name, "Content-Encoding") {
			for _, value := range values {
				if coding := strings.TrimSpace(value); coding != "" && !strings.EqualFold(coding, "identity") {
					return fmt.Errorf("multipart content encoding is unsupported")
				}
			}
		}
	}
	return nil
}

func findDelimiter(body, marker []byte, from int) (delimiter, bool) {
	for from <= len(body) {
		found := bytes.Index(body[from:], marker)
		if found < 0 {
			break
		}
		start := from + found
		from = start + 1
		if start != 0 && (start < 2 || !bytes.Equal(body[start-2:start], []byte("\r\n"))) {
			continue
		}
		end := start + len(marker)
		closing := false
		if bytes.HasPrefix(body[end:], []byte("--")) {
			closing = true
			end += 2
		}
		for end < len(body) && (body[end] == ' ' || body[end] == '\t') {
			end++
		}
		if end == len(body) && closing {
			return delimiter{start, end, true}, true
		}
		if end+2 <= len(body) && bytes.Equal(body[end:end+2], []byte("\r\n")) {
			return delimiter{start, end + 2, closing}, true
		}
	}
	return delimiter{}, false
}

func Parse(headers http.Header, body []byte) (*Document, error) {
	if len(body) > MaxBodyBytes {
		return nil, fmt.Errorf("multipart body exceeds size limit")
	}
	if err := identity(headers); err != nil {
		return nil, err
	}
	media, params, err := contentType(headers)
	if err != nil || media != "multipart/form-data" {
		return nil, fmt.Errorf("multipart location requires multipart/form-data")
	}
	boundary := params["boundary"]
	var sink bytes.Buffer
	writer := multipart.NewWriter(&sink)
	if boundary == "" || writer.SetBoundary(boundary) != nil {
		return nil, fmt.Errorf("invalid multipart boundary")
	}
	marker := []byte("--" + boundary)
	current, ok := findDelimiter(body, marker, 0)
	if !ok {
		return nil, fmt.Errorf("multipart boundary is missing")
	}
	doc := &Document{Boundary: boundary, Params: params, Preamble: body[:current.start]}
	for !current.closing {
		if len(doc.Parts) >= MaxParts {
			return nil, fmt.Errorf("multipart part limit exceeded")
		}
		next, ok := findDelimiter(body, marker, current.end)
		if !ok || next.start < current.end+2 {
			return nil, fmt.Errorf("multipart closing boundary or part framing is invalid")
		}
		region := body[current.end : next.start-2]
		headerEnd := 0
		if bytes.HasPrefix(region, []byte("\r\n")) {
			headerEnd = 2
		} else if index := bytes.Index(region, []byte("\r\n\r\n")); index >= 0 {
			headerEnd = index + 4
		}
		if headerEnd == 0 || headerEnd > 64<<10 {
			return nil, fmt.Errorf("multipart headers are missing or too large")
		}
		parsed, err := textproto.NewReader(bufio.NewReader(bytes.NewReader(region[:headerEnd]))).ReadMIMEHeader()
		if err != nil {
			return nil, fmt.Errorf("invalid multipart part headers")
		}
		part := Part{Headers: http.Header(parsed), RawHeader: region[:headerEnd], Data: region[headerEnd:], Tail: body[current.start+len(marker) : current.end]}
		values := part.Headers.Values("Content-Disposition")
		if len(values) > 1 {
			return nil, fmt.Errorf("ambiguous multipart Content-Disposition")
		}
		if len(values) == 1 {
			part.Disposition, part.Params, err = mime.ParseMediaType(values[0])
			if err != nil {
				return nil, fmt.Errorf("invalid multipart Content-Disposition")
			}
			if part.Disposition == "form-data" {
				part.Name = part.Params["name"]
			}
			part.Filename, part.File = part.Params["filename"]
			if !utf8.ValidString(part.Name) {
				return nil, fmt.Errorf("multipart part name is not UTF-8")
			}
		}
		doc.Parts = append(doc.Parts, part)
		current = next
	}
	doc.CloseTail = body[current.start+len(marker) : current.end]
	doc.Epilogue = body[current.end:]
	return doc, nil
}

func Address(path string) (string, int, error) {
	if strings.HasPrefix(path, "index:") {
		value := strings.TrimPrefix(path, "index:")
		index, err := strconv.Atoi(value)
		if err != nil || index < 0 || index >= MaxParts || strconv.Itoa(index) != value {
			return "", -1, fmt.Errorf("multipart index must be canonical and within part limits")
		}
		return "", index, nil
	}
	name := strings.TrimPrefix(path, "name:")
	if name == "" || !utf8.ValidString(name) || strings.ContainsAny(name, "\r\n\x00") {
		return "", -1, fmt.Errorf("invalid multipart part name")
	}
	return name, -1, nil
}
func NamedAddress(name string) string {
	if strings.HasPrefix(name, "name:") || strings.HasPrefix(name, "index:") {
		return "name:" + name
	}
	return name
}
func (doc *Document) ValidateAddress(path string) error {
	index, err := doc.selectPart(path)
	if err != nil {
		return err
	}
	_, ordinal, err := Address(path)
	if err != nil {
		return err
	}
	if ordinal >= 0 && index < 0 {
		return fmt.Errorf("multipart index is outside the captured body")
	}
	return nil
}
func (doc *Document) selectPart(path string) (int, error) {
	name, index, err := Address(path)
	if err != nil {
		return -1, err
	}
	if index >= 0 {
		if index >= len(doc.Parts) {
			return -1, nil
		}
		return index, nil
	}
	found := -1
	for i, part := range doc.Parts {
		if part.Name == name {
			if found >= 0 {
				return -1, fmt.Errorf("multipart name is ambiguous; select an explicit index")
			}
			found = i
		}
	}
	return found, nil
}
func contentIdentity(part Part) error {
	if err := identity(part.Headers); err != nil {
		return err
	}
	values := part.Headers.Values("Content-Transfer-Encoding")
	if len(values) > 1 {
		return fmt.Errorf("ambiguous multipart transfer encoding")
	}
	if len(values) == 1 {
		switch strings.ToLower(strings.TrimSpace(values[0])) {
		case "", "binary", "8bit":
		case "7bit":
			for _, value := range part.Data {
				if value > 127 {
					return fmt.Errorf("invalid 7bit part data")
				}
			}
		default:
			return fmt.Errorf("multipart transfer encoding is unsupported")
		}
	}
	return nil
}

func (doc *Document) Value(location, path string) ([]byte, bool, error) {
	index, err := doc.selectPart(path)
	if err != nil || index < 0 {
		return nil, false, err
	}
	part := doc.Parts[index]
	switch location {
	case "multipart":
		if part.File {
			return nil, false, fmt.Errorf("multipart text selector points to a file")
		}
		if err := contentIdentity(part); err != nil {
			return nil, false, err
		}
		if !utf8.Valid(part.Data) {
			return nil, false, fmt.Errorf("multipart text is not UTF-8")
		}
		return part.Data, true, nil
	case "multipart-file":
		if !part.File {
			return nil, false, fmt.Errorf("multipart file selector points to text")
		}
		if err := contentIdentity(part); err != nil {
			return nil, false, err
		}
		return part.Data, true, nil
	case "multipart-filename":
		if !part.File {
			return nil, false, nil
		}
		if !utf8.ValidString(part.Filename) {
			return nil, false, fmt.Errorf("multipart filename is not UTF-8")
		}
		return []byte(part.Filename), true, nil
	case "multipart-content-type":
		values := part.Headers.Values("Content-Type")
		if len(values) > 1 {
			return nil, false, fmt.Errorf("ambiguous multipart part Content-Type")
		}
		if len(values) == 0 {
			return nil, false, nil
		}
		if !utf8.ValidString(values[0]) {
			return nil, false, fmt.Errorf("part Content-Type is not UTF-8")
		}
		return []byte(values[0]), true, nil
	}
	return nil, false, fmt.Errorf("unknown multipart location")
}

func Value(headers http.Header, body []byte, location, path string) ([]byte, bool, error) {
	doc, err := Parse(headers, body)
	if err != nil {
		return nil, false, err
	}
	return doc.Value(location, path)
}
