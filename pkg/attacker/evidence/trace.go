package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
	"github.com/kaitoz11/reqfuzzy/pkg/attacker/jsonutil"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

type bodyEvidence struct {
	SHA256   string          `json:"sha256"`
	Size     int             `json:"size"`
	Encoding string          `json:"encoding,omitempty"`
	Data     json.RawMessage `json:"data,omitempty"`
	Omitted  bool            `json:"omitted,omitempty"`
}
type requestEvidence struct {
	Method  string       `json:"method"`
	URL     string       `json:"url"`
	Host    string       `json:"host"`
	Headers http.Header  `json:"headers"`
	Body    bodyEvidence `json:"body"`
}
type responseEvidence struct {
	Status  int          `json:"status"`
	Headers http.Header  `json:"headers"`
	Body    bodyEvidence `json:"body"`
}
type stepEvidence struct {
	ID        string           `json:"id"`
	Actor     string           `json:"actor"`
	Prepared  requestEvidence  `json:"prepared"`
	Sent      *requestEvidence `json:"sent,omitempty"`
	Mutated   *requestEvidence `json:"mutated_before_hooks,omitempty"`
	Response  responseEvidence `json:"response"`
	Extracted []string         `json:"extracted_names"`
}
type runEvidence struct {
	Name       string         `json:"name"`
	FailedStep string         `json:"failed_step,omitempty"`
	Steps      []stepEvidence `json:"steps"`
	Variables  []string       `json:"variable_names"`
}

func sensitiveName(name string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(name, "-", ""), "_", ""))
	switch normalized {
	case "authorization", "proxyauthorization", "cookie", "setcookie", "password", "passwd", "token", "accesstoken", "refreshtoken", "secret", "clientsecret", "apikey", "signingkey", "session", "sessionid", "referencesid", "otp", "nonce":
		return true
	}
	return strings.HasSuffix(normalized, "token") || strings.HasSuffix(normalized, "secret") || strings.HasSuffix(normalized, "password") || strings.HasSuffix(normalized, "apikey") || strings.HasSuffix(normalized, "signature")
}
func listed(name string, list []string) bool {
	for _, candidate := range list {
		if strings.EqualFold(name, candidate) {
			return true
		}
	}
	return false
}
func (s *Store) headers(headers http.Header) http.Header {
	result := headers.Clone()
	if !s.sensitive {
		for name := range result {
			if sensitiveName(name) || listed(name, s.redaction.Headers) {
				result[name] = []string{"[REDACTED]"}
			}
		}
	}
	return result
}
func (s *Store) url(raw string) string {
	if s.sensitive {
		return raw
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "[UNAVAILABLE]"
	}
	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return "[UNAVAILABLE]"
	}
	for key := range query {
		if sensitiveName(key) || listed(key, s.redaction.QueryKeys) {
			query[key] = []string{"[REDACTED]"}
		}
	}
	parsed.RawQuery = query.Encode()
	if parsed.User != nil {
		parsed.User = url.User("[REDACTED]")
	}
	return parsed.String()
}

func (s *Store) body(raw []byte) bodyEvidence {
	digest := sha256.Sum256(raw)
	result := bodyEvidence{SHA256: hex.EncodeToString(digest[:]), Size: len(raw)}
	if s.sensitive {
		result.Encoding = "base64"
		result.Data, _ = json.Marshal(base64.StdEncoding.EncodeToString(raw))
		return result
	}
	if jsonutil.ValidateUnique(raw) != nil {
		result.Omitted = true
		return result
	}
	redacted := append([]byte(nil), raw...)
	for _, path := range s.redaction.JSONPaths {
		if gjson.GetBytes(redacted, path).Exists() {
			updated, err := sjson.SetRawBytes(redacted, path, []byte(`"[REDACTED]"`))
			selected := gjson.GetBytes(updated, path)
			if err != nil || selected.Type != gjson.String || selected.String() != "[REDACTED]" {
				result.Omitted = true
				return result
			}
			redacted = updated
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(redacted))
	decoder.UseNumber()
	var value any
	if decoder.Decode(&value) != nil {
		result.Omitted = true
		return result
	}
	redactKeys(value)
	result.Data, _ = json.Marshal(value)
	result.Encoding = "json"
	return result
}
func redactKeys(value any) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if sensitiveName(key) {
				typed[key] = "[REDACTED]"
			} else {
				redactKeys(child)
			}
		}
	case []any:
		for _, child := range typed {
			redactKeys(child)
		}
	}
}
func (s *Store) request(request flow.RequestSnapshot) requestEvidence {
	return requestEvidence{Method: request.Method, URL: s.url(request.RawURL), Host: request.Host, Headers: s.headers(request.Headers), Body: s.body(request.Body)}
}
func names(values flow.Variables) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
func (s *Store) run(result flow.RunResult) runEvidence {
	output := runEvidence{Name: result.FlowName, FailedStep: result.FailedStepID, Steps: []stepEvidence{}, Variables: names(result.Variables)}
	for _, step := range result.Steps {
		trace := stepEvidence{ID: step.StepID, Actor: step.Actor, Prepared: s.request(step.Request), Response: responseEvidence{Status: step.StatusCode, Headers: s.headers(step.ResponseHeaders), Body: s.body(step.ResponseBody)}, Extracted: names(step.Extracted)}
		if step.SentRequest != nil {
			sent := s.request(*step.SentRequest)
			trace.Sent = &sent
		}
		if step.MutationRequest != nil {
			mutated := s.request(*step.MutationRequest)
			trace.Mutated = &mutated
		}
		output.Steps = append(output.Steps, trace)
	}
	return output
}
