# HAR capture to executable flow

**Status:** approved next milestone on 2026-10-28, following the flow mutation slice

## Goal

Given a HAR 1.2 capture with requests and responses, reqfuzzy writes stable named raw-request files and suggests an executable flow. The suggestion shows which JSON response value appears in a later request and where it is bound. A person reviews and edits the YAML before replay. Import and inference are offline: neither opens a target connection.

The parser follows the [HAR format specification](https://webperfwg.org/specs/HAR/Overview.html) for request URLs, ordered headers, `postData`, and optional response content encoding.

## Package and API

Add `pkg/attacker/capture`, which depends on `pkg/attacker/flow`; the flow package does not import capture.

```go
type Exchange struct {
    Name            string
    Method          string
    URL             string
    RequestRaw      []byte
    ResponseStatus  int
    ResponseBody    []byte
    ResponseBodyPresent bool
}

type Capture struct { Exchanges []Exchange }
type Link struct {
    FromStep, FromJSONPath string
    ToStep, ToLocation, ToPath string
    Prefix, Confidence string
}
type Suggestion struct {
    Flow  flow.Flow
    Links []Link
}

func ParseHAR(data []byte) (Capture, error)
func (c Capture) WriteRequests(directory string) (map[string]string, error)
func SuggestFlow(c Capture) (Suggestion, error)
func (s Suggestion) YAML() ([]byte, error)
```

`WriteRequests` returns request name to absolute file path for `RequestStore.RegisterRequestFilePath`. The caller chooses an output directory. Documentation uses `.reqfuzzy/captures/<name>/requests/`, and `.reqfuzzy/` is ignored by Git because imported traffic can contain credentials.

## HAR parsing and request materialization

- Accept `log.version: "1.2"` and a nonempty `log.entries` array. Ignore a UTF-8 BOM. Reject malformed JSON, unsupported versions, missing method or absolute `http`/`https` URL, malformed header names or values, and an entry that cannot be replayed. Errors identify the HAR entry number. Parse all entries before writing files.
- Preserve entry array order. Assign deterministic names `0001_get_api_login`, `0002_post_api_transfer`, and so on from one-based index, lower-case method, and a sanitized path slug. The index prevents collisions; names contain only letters, digits, `_`, and `-`, with a bounded slug length.
- Build each raw request as `METHOD path?query HTTP/1.1`, followed by HAR headers in their original order, a `Host` header if absent, a blank line, and body bytes. Normalize an HTTP/2 capture to an HTTP/1.1 raw request line for the existing parser. Exclude captured `Content-Length` and `Transfer-Encoding` because the transport regenerates framing after mutation.
- If `postData.text` is present, use its UTF-8 bytes exactly. If text is absent and `postData.params` is present for `application/x-www-form-urlencoded`, encode the ordered name/value pairs. Reject params-only multipart or other unreconstructable bodies with an explicit entry error. Add `Content-Type` from `postData.mimeType` when no header supplies it.
- A missing response has status zero. A missing `response.content.text` leaves `ResponseBodyPresent` false for inference, even if a response status exists. When `response.content.encoding` is `base64`, decode `text`; when omitted, use its UTF-8 bytes. Reject an unsupported encoding or invalid base64 rather than infer from corrupted content.
- `WriteRequests` creates the target directory with mode `0700` and each file with mode `0600`. Re-importing identical bytes is idempotent. If a generated name already contains different bytes, return an error without overwriting it. Generated names cannot escape the output directory.

## Inference

`SuggestFlow` creates one step for each exchange in capture order. Its `request` is the exchange name; its `id` is the same name. If a response is present with an HTTP status from 100 to 599, set `expect_status` to that observed status. The flow name is `har-suggestion`.

Only JSON scalar values from response bodies are candidate sources. Traverse nested objects and arrays deterministically, producing `gjson` paths such as `data.transactionId` and `items.0.id`. Escape special key characters with `gjson.Escape` and escape a leading colon as well, so both `gjson` extraction and `sjson` binding target the same key. Strings shorter than six characters, numbers with fewer than four digits, booleans, nulls, objects, and arrays are excluded. This suppresses common accidental matches. A response with absent, invalid, non-JSON, or duplicate-key JSON content contributes no candidates.

Search later requests for an exact scalar value in these runnable destinations:

- URL query values: `location: query`, with the query key as `path`. Skip keys with more than one value because the runner replaces the entire key.
- Header values: `location: header`, excluding `Host`, `Cookie`, `Content-Length`, `Transfer-Encoding`, and other framing headers. Skip repeated header names for the same reason. Recognize `Authorization: Bearer <token>` case insensitively and preserve its original scheme prefix.
- JSON body scalar leaves: `location: json`, with an `sjson` path as `path`; match both value and JSON type.

Only emit a binding when the matching value has exactly one eligible source path in all earlier responses. Ambiguous values produce no automatic binding. One source extraction can feed multiple later bindings. Each emitted link adds an extraction to the source step and a binding to the destination step. Generated variable names are deterministic and unique. `Link` records source/destination step and paths, the optional prefix, and a confidence value (`high` for exact strings of at least eight characters and Bearer tokens; `medium` for shorter eligible strings and numbers). It never stores the secret value itself.

The existing flow binding model gains an optional `prefix` field. It is valid only for `header` and `query`; the runner concatenates `prefix + extracted text` at binding time. JSON bindings retain exact type and reject a prefix. Existing flow YAML remains valid.

`Suggestion.YAML()` marshals only the `flow.Flow`. The separate `Links` metadata supports review without violating the strict flow YAML schema. The suggested YAML must load through `flow.LoadYAML` and run through `flow.Runner` after the output requests are registered. No suggestion runs automatically.

## Acceptance

- A three-entry HAR fixture representing login → create transfer → confirm imports into stable raw request files. The first response's token is inferred into a later Bearer header; the second response's numeric transaction ID is inferred into the confirmation JSON body.
- The returned YAML passes `flow.LoadYAML`; the generated request files parse with `rawreq.ParseRawRequest`; the suggested flow executes against a local `httptest` API after an operator registers the files.
- A base64 response, a missing response body, an ambiguous repeated value, and a short common value have explicit tests.
- Re-import is idempotent; a conflicting generated file is left untouched; output names cannot escape the output directory.
- `go test -race ./...` and `go vet ./...` pass without a live target.
