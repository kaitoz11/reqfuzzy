package multipartbody

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"mime"
	"net/http"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/http/httpguts"
)

func ValidValue(location, value string) error {
	if location == "multipart-file" {
		if len(value) > base64.StdEncoding.EncodedLen(MaxBodyBytes) {
			return fmt.Errorf("multipart file value exceeds size limit")
		}
		if _, err := base64.StdEncoding.Strict().DecodeString(value); err != nil {
			return fmt.Errorf("multipart file value must be base64")
		}
		return nil
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("multipart value is not UTF-8")
	}
	if location == "multipart-filename" || location == "multipart-content-type" {
		if !httpguts.ValidHeaderFieldValue(value) || strings.ContainsAny(value, "\r\n\x00") {
			return fmt.Errorf("invalid multipart metadata value")
		}
		for _, character := range value {
			if character < 32 || character == 127 {
				return fmt.Errorf("invalid multipart metadata control byte")
			}
		}
	}
	return nil
}

func editHeader(raw []byte, name string, value *string) []byte {
	lines := bytes.SplitAfter(raw, []byte("\n"))
	var blocks [][]byte
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		if bytes.Equal(line, []byte("\r\n")) || bytes.Equal(line, []byte("\n")) {
			break
		}
		if (line[0] == ' ' || line[0] == '\t') && len(blocks) > 0 {
			blocks[len(blocks)-1] = append(append([]byte(nil), blocks[len(blocks)-1]...), line...)
		} else {
			blocks = append(blocks, line)
		}
	}
	var result bytes.Buffer
	replaced := false
	for _, block := range blocks {
		key, _, _ := bytes.Cut(block, []byte(":"))
		if strings.EqualFold(string(key), name) {
			if value != nil && !replaced {
				fmt.Fprintf(&result, "%s: %s\r\n", name, *value)
				replaced = true
			}
			continue
		}
		result.Write(block)
	}
	if value != nil && !replaced {
		fmt.Fprintf(&result, "%s: %s\r\n", name, *value)
	}
	result.WriteString("\r\n")
	return result.Bytes()
}

func partHeader(part *Part, name string, value *string) {
	part.RawHeader = editHeader(part.RawHeader, name, value)
	part.Headers = part.Headers.Clone()
	if value == nil {
		part.Headers.Del(name)
	} else {
		part.Headers.Set(name, *value)
	}
}

func newPart(name string, file bool, filename string) Part {
	params := map[string]string{"name": name}
	if file {
		params["filename"] = filename
	}
	value := mime.FormatMediaType("form-data", params)
	part := Part{Name: name, File: file, Filename: filename, Disposition: "form-data", Params: params, Headers: make(http.Header), Tail: []byte("\r\n"), RawHeader: []byte("\r\n")}
	partHeader(&part, "Content-Disposition", &value)
	if file {
		contentType := "application/octet-stream"
		partHeader(&part, "Content-Type", &contentType)
	}
	return part
}

func collision(data []byte, boundary string) bool {
	marker := []byte("--" + boundary)
	if _, found := findDelimiter(data, marker, 0); found {
		return true
	}
	start := bytes.LastIndex(data, []byte("\r\n"))
	if start >= 0 {
		data = data[start+2:]
	}
	return bytes.HasPrefix(data, marker) && len(bytes.Trim(data[len(marker):], " \t")) == 0
}

func (doc *Document) marshal() (string, []byte, error) {
	boundary := doc.Boundary
	conflicts := func(candidate string) bool {
		if collision(doc.Preamble, candidate) {
			return true
		}
		for _, part := range doc.Parts {
			if collision(part.Data, candidate) || collision(part.RawHeader, candidate) {
				return true
			}
		}
		return false
	}
	if conflicts(boundary) {
		found := false
		for attempt := 0; attempt < 10; attempt++ {
			hash := sha256.New()
			hash.Write([]byte(doc.Boundary))
			fmt.Fprintf(hash, "/%d/", attempt)
			for _, part := range doc.Parts {
				hash.Write(part.RawHeader)
				hash.Write(part.Data)
			}
			sum := hash.Sum(nil)
			boundary = "reqfuzzy-" + hex.EncodeToString(sum[:16])
			if !conflicts(boundary) {
				found = true
				break
			}
		}
		if !found {
			return "", nil, fmt.Errorf("could not choose multipart boundary")
		}
	}
	var output bytes.Buffer
	write := func(data []byte) error {
		if output.Len()+len(data) > MaxBodyBytes {
			return fmt.Errorf("multipart body exceeds size limit")
		}
		_, err := output.Write(data)
		return err
	}
	if err := write(doc.Preamble); err != nil {
		return "", nil, err
	}
	for _, part := range doc.Parts {
		for _, data := range [][]byte{[]byte("--" + boundary), part.Tail, part.RawHeader, part.Data, []byte("\r\n")} {
			if err := write(data); err != nil {
				return "", nil, err
			}
		}
	}
	for _, data := range [][]byte{[]byte("--" + boundary), doc.CloseTail, doc.Epilogue} {
		if err := write(data); err != nil {
			return "", nil, err
		}
	}
	return boundary, output.Bytes(), nil
}

// Edit returns new headers/body after validating the complete result. No input
// map or byte slice is changed on error.
func Edit(headers http.Header, body []byte, location, path, action, value string) (http.Header, []byte, error) {
	if action != "set" && action != "remove" && action != "append" && action != "prepend" {
		return nil, nil, fmt.Errorf("unsupported multipart action")
	}
	if action != "remove" {
		if err := ValidValue(location, value); err != nil {
			return nil, nil, err
		}
	}
	doc, err := Parse(headers, body)
	if err != nil {
		return nil, nil, err
	}
	index, err := doc.selectPart(path)
	if err != nil {
		return nil, nil, err
	}
	if index < 0 {
		name, ordinal, err := Address(path)
		if err != nil {
			return nil, nil, err
		}
		if action != "set" || ordinal >= 0 || location == "multipart-file" {
			return nil, nil, fmt.Errorf("multipart target does not exist")
		}
		doc.Parts = append(doc.Parts, newPart(name, location == "multipart-filename", value))
		index = len(doc.Parts) - 1
		if len(doc.Parts) > MaxParts {
			return nil, nil, fmt.Errorf("multipart part limit exceeded")
		}
	}
	part := &doc.Parts[index]
	var expected []byte
	exists := true
	if location == "multipart" && part.File {
		return nil, nil, fmt.Errorf("multipart text selector points to a file")
	}
	if location == "multipart-file" && !part.File {
		return nil, nil, fmt.Errorf("multipart file selector points to text")
	}
	if action == "remove" {
		switch location {
		case "multipart", "multipart-file":
			doc.Parts = append(doc.Parts[:index], doc.Parts[index+1:]...)
		case "multipart-filename":
			if !part.File {
				return nil, nil, fmt.Errorf("multipart filename is missing")
			}
			delete(part.Params, "filename")
			part.File = false
			part.Filename = ""
			header := mime.FormatMediaType(part.Disposition, part.Params)
			partHeader(part, "Content-Disposition", &header)
		case "multipart-content-type":
			if len(part.Headers.Values("Content-Type")) != 1 {
				return nil, nil, fmt.Errorf("multipart Content-Type is absent or ambiguous")
			}
			partHeader(part, "Content-Type", nil)
		default:
			return nil, nil, fmt.Errorf("unknown multipart location")
		}
		exists = false
	} else {
		if location == "multipart" || location == "multipart-file" {
			if err := contentIdentity(*part); err != nil {
				return nil, nil, err
			}
		}
		expected = []byte(value)
		if location == "multipart-file" {
			expected, _ = base64.StdEncoding.Strict().DecodeString(value)
		}
		if action == "append" || action == "prepend" {
			current, found, err := doc.Value(location, path)
			if err != nil || !found {
				if err == nil {
					err = fmt.Errorf("multipart value is missing")
				}
				return nil, nil, err
			}
			if action == "append" {
				expected = append(append([]byte(nil), current...), expected...)
			} else {
				expected = append(append([]byte(nil), expected...), current...)
			}
		}
		if location != "multipart-file" {
			if err := ValidValue(location, string(expected)); err != nil {
				return nil, nil, err
			}
		}
		switch location {
		case "multipart", "multipart-file":
			part.Data = expected
		case "multipart-filename":
			if part.Params == nil {
				part.Params = make(map[string]string)
			}
			if part.Disposition == "" {
				part.Disposition = "form-data"
			}
			part.Params["filename"] = string(expected)
			part.Filename = string(expected)
			part.File = true
			header := mime.FormatMediaType(part.Disposition, part.Params)
			partHeader(part, "Content-Disposition", &header)
		case "multipart-content-type":
			header := string(expected)
			partHeader(part, "Content-Type", &header)
		default:
			return nil, nil, fmt.Errorf("unknown multipart location")
		}
	}
	boundary, result, err := doc.marshal()
	if err != nil {
		return nil, nil, err
	}
	updated := headers.Clone()
	if boundary != doc.Boundary {
		doc.Params["boundary"] = boundary
		contentType := mime.FormatMediaType("multipart/form-data", doc.Params)
		for key := range updated {
			if strings.EqualFold(key, "Content-Type") {
				updated[key] = []string{contentType}
			}
		}
	}
	parsed, err := Parse(updated, result)
	if err != nil {
		return nil, nil, err
	}
	if exists {
		actual, found, err := parsed.Value(location, path)
		if err != nil || !found || !bytes.Equal(actual, expected) {
			return nil, nil, fmt.Errorf("multipart edit did not apply")
		}
	}
	return updated, result, nil
}
