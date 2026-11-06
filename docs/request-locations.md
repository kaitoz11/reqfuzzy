# Request bindings and mutation locations

Use the same location names in step `bind` entries, `flow compare --location`, and a journey test's `target`. Bindings apply fresh extracted values before the selected mutation; final JavaScript hooks then prepare or sign the resulting request.

| Location | Address in `path` | Set | Remove | Append/prepend |
|---|---|---|---|---|
| `json` | Literal JSON field/index path | Typed scalar, including null | Existing member/element | Existing unique string |
| `header` | Header name | Replace all case variants | Existing header | One existing value |
| `query` | Decoded query key | Replace all selected occurrences | All selected occurrences | One existing value |
| `path` | Quoted zero-based segment slot | Replace one escaped segment | Delete the selected slot | Existing segment text |
| `form` | Decoded URL-encoded body key | Replace all selected occurrences | All selected occurrences | One existing value |
| `multipart` | Unique part name or `index:N` | UTF-8 text; can create a named text part | Selected whole text part | Existing text bytes |
| `multipart-file` | Unique part name or `index:N` | Base64 file bytes; existing file required | Selected whole file part | Decoded bytes, encoded as base64 input |
| `multipart-filename` | Unique part name or `index:N` | Full filename; can create an empty file placeholder | Filename attribute; content stays | Existing filename text |
| `multipart-content-type` | Unique part name or `index:N` | Part Content-Type header | Part Content-Type header | Existing header text |
| `cookie` | Case-sensitive cookie name | Override all selected-name values for this request | Suppress selected-name values for this request | One current value from the request/client/jar |

Remove requires an existing target and takes no value. Append/prepend take string payloads. Null is a JSON-only value. Transport-managed framing headers and Host removal remain unsupported. Existing captured Cookie headers are still removed; current request bindings, client defaults, and the actor's live jar provide cookies.

JSON numbers additionally support `add` and `multiply` with exact numeric operands. These arithmetic actions use the current bound number and do not coerce strings or apply to other locations. [Payload sets and templates](payloads.md) describe reusable sources and string transformations.

## Named cookies

Extract a single response `Set-Cookie` value and bind it into a later request:

```yaml
steps:
  - id: session
    request: session
    extract:
      - {name: sid, cookie: reference_sid}
  - id: transfer
    request: transfer
    bind:
      - {location: cookie, path: reference_sid, variable: sid}
    before_send: sign
```

Each extraction requires exactly one selector, `json` or `cookie`. A response-cookie selector must match exactly one valid `Set-Cookie` name; missing or duplicated names stop extraction. The result is the header's value, not a browser cookie-store query. Existing automatic jar handling remains available without explicit bindings.

Use `target: {step: transfer, location: cookie, path: reference_sid}` for a campaign. Names are case sensitive. Values follow HTTP cookie syntax and are not URL-decoded or silently sanitized; semicolons, quotes, control bytes, and unsupported non-ASCII values are rejected. Percent sequences remain literal text. Set/remove affect all occurrences of the selected name on the chosen request; append/prepend require exactly one current occurrence, including common cookies and matching jar entries.

An edit overlays that request's live session without writing the override to the shared jar or changing client defaults. Unrelated cookies are retained, and response `Set-Cookie` updates still reach the actor's jar. The next request therefore uses the server's current session. Custom HTTP transports and dump configuration are preserved; per-request adapter resources are cleaned up.

Explicit cookie edits are visible as a Cookie header before final hooks. Other automatic jar cookies remain transport-supplied; a hook signing an entire Cookie header must account for that distinction. Hooks may change or erase an edited value; proof checks every matching named cookie in the observed sent header, so restoration, duplication, or failed removal is inconclusive.

Cookie lookup follows the executing Go HTTP client's Host semantics, including the [Go 1.26 change](https://github.com/golang/go/commit/69e82796322bbff60b522534a8a6eacb2bf1ebba). The module continues to support Go 1.24.

## Path segments

For `/api/items/old/confirm`, slot `"2"` is `old`. Indices count empty internal/trailing slots and split the escaped path before decoding, so `%2F` remains inside one segment. Values are UTF-8 text escaped with path-segment rules. Dot-only replacements are escaped, and a leading `//` result is rejected to preserve the target origin.

```yaml
bind:
  - {location: path, path: "2", variable: item_id}
```

In a campaign, use `target: {step: read, location: path, path: "2"}`. A set/append/prepend proof compares the selected escaped segment against the sent request. Removal compares the complete resulting escaped path because deletion shifts later indices. Removing the root's empty slot is rejected as a no-op. Other path segments and raw query bytes retain their encoding and order.

## URL-encoded form bodies

`form` supports UTF-8 `application/x-www-form-urlencoded` with one unambiguous Content-Type. Non-UTF-8 charsets, malformed percent encoding, invalid decoded UTF-8, and non-identity Content-Encoding are rejected. For multipart bodies, use the locations below.

For a captured `POST /submit` with body `csrf=old&amount=10&note=hello%20world`:

```yaml
bind:
  - {location: form, path: csrf, variable: csrf_token}
before_send: sign
```

A campaign targeting `amount` can use:

```yaml
target: {step: submit, location: form, path: amount}
cases:
  - {id: negative, action: set, value: -10}
  - {id: missing, action: remove}
```

Form values use exact scalar text. A replacement containing `&`, `=`, `/`, or `+` is encoded as data. Unrelated fields retain their original bytes, order, and escapes. Set preserves the first selected key's spelling and replaces its repeated values with one; remove deletes all selected occurrences. Append/prepend reject repeated selected keys.

Static location validation runs before clients or prerequisites in authored flows and campaigns. The CLI also validates a `compare` target before its baseline. Go callers constructing a mutation callback can call `Runner.PreflightTarget` for the same static validation. Runtime field existence is checked after bindings, since a binding may create a field absent from the capture.

Campaign proof parses the actual captured sent body with its actual headers. A restored field, unavailable body, unsupported encoding, or changed media type is unassessable. Normal opaque form bodies are omitted from redacted evidence with hashes retained; the existing JSON-body redaction policy applies when bytes are valid JSON. Sensitive evidence is an explicit opt-in.

HAR inference uses the existing unique-source and minimum-length rules for form values. Repeated form keys and malformed/unsupported form encoding are left unresolved; import itself remains offline. Inferred and authored form dependencies appear in `flow show`.

## Multipart bodies

Use `multipart/form-data` with one boundary-bearing Content-Type and identity outer Content-Encoding. Addresses are unique literal part names; `name:literal` escapes names beginning with `name:` or `index:`. `index:N` selects an absolute zero-based part ordinal from 0 through 999, including repeated names. Names are case sensitive; duplicate named selection fails. Named selectors recognize only `form-data` dispositions; explicit ordinals can address other raw parts. Deleting a whole part shifts later ordinals, so proof compares the complete resulting body for ordinal removals.

```yaml
bind:
  - {location: multipart, path: nonce, variable: nonce}
  - {location: multipart-filename, path: file, variable: filename}
  - {location: multipart-file, path: file, variable: file_data}
before_send: sign
```

`file_data` must be a base64 string and cannot use a binding prefix. File append/prepend decode both inputs and combine bytes. Filename set can create an empty named file placeholder before a later file-content binding; full logical filenames such as `../test.bin` remain intact. Filename removal retains the part's bytes; text/file removal deletes the selected whole part. Text and metadata use scalar text; metadata control bytes are rejected. Null and arithmetic remain JSON-only.

The bounded raw parser supports CRLF framing, preamble/epilogue, at most 1,000 parts, 64 KiB per part's headers, and 16 MiB total. Untouched part bytes, raw headers, order, and delimiter suffixes are preserved. A payload colliding with the original delimiter causes deterministic boundary replacement before signing. Selected content supports identity Content-Encoding and binary/8bit/valid 7bit transfer encodings; other encoded content is refused. Unselected opaque parts retain their bytes.

Static preflight checks the captured structure and unambiguous address before clients. Runtime edits validate the result before applying it. Campaign proof parses actual sent bytes and headers; unavailable bodies, malformed/ambiguous parts, overwritten values, or unsupported content encodings remain inconclusive. Normal evidence hashes/omits opaque multipart bodies; `--include-sensitive` stores byte-exact base64 privately. HAR text represents only its supplied UTF-8 bytes; params-only multipart cannot recover file data. Raw request files can carry arbitrary binary bytes.

See the [upload project](../examples/multipart/README.md) for binary signing, generated filename cases, downstream state checks, and reconstruction.
