# Request bindings and mutation locations

Use the same location names in step `bind` entries, `flow compare --location`, and a journey test's `target`. Bindings apply fresh extracted values before the selected mutation; final JavaScript hooks then prepare or sign the resulting request.

| Location | Address in `path` | Set | Remove | Append/prepend |
|---|---|---|---|---|
| `json` | Literal JSON field/index path | Typed scalar, including null | Existing member/element | Existing unique string |
| `header` | Header name | Replace all case variants | Existing header | One existing value |
| `query` | Decoded query key | Replace all selected occurrences | All selected occurrences | One existing value |
| `path` | Quoted zero-based segment slot | Replace one escaped segment | Delete the selected slot | Existing segment text |
| `form` | Decoded URL-encoded body key | Replace all selected occurrences | All selected occurrences | One existing value |

Remove requires an existing target and takes no value. Append/prepend take string payloads. Null is a JSON-only value. Transport-managed framing headers and Host removal remain unsupported. Existing captured Cookie headers are still replaced by each actor's current cookie jar; named cookie mutations are a separate increment.

## Path segments

For `/api/items/old/confirm`, slot `"2"` is `old`. Indices count empty internal/trailing slots and split the escaped path before decoding, so `%2F` remains inside one segment. Values are UTF-8 text escaped with path-segment rules. Dot-only replacements are escaped, and a leading `//` result is rejected to preserve the target origin.

```yaml
bind:
  - {location: path, path: "2", variable: item_id}
```

In a campaign, use `target: {step: read, location: path, path: "2"}`. A set/append/prepend proof compares the selected escaped segment against the sent request. Removal compares the complete resulting escaped path because deletion shifts later indices. Removing the root's empty slot is rejected as a no-op. Other path segments and raw query bytes retain their encoding and order.

## URL-encoded form bodies

`form` supports UTF-8 `application/x-www-form-urlencoded` with one unambiguous Content-Type. Non-UTF-8 charsets, malformed percent encoding, invalid decoded UTF-8, and non-identity Content-Encoding are rejected. Multipart bodies require separate support.

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
