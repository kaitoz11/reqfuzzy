# Multipart journeys and binary scripts

Add multipart binding, mutation, conservative inference, sent-request proof, and binary signing to the current Go tool. Preserve existing APIs and Go 1.24. Continue under the user's standing reviewed/passing-CI development integration approval.

## Multipart model

New locations use a unique literal part name, `name:literal` to escape names beginning with `name:`/`index:`, or `index:N` for a zero-based canonical absolute part ordinal below 1,000: `multipart` for UTF-8 text, `multipart-file` for base64-encoded file bytes, `multipart-filename` for the full logical filename, and `multipart-content-type` for the selected part's Content-Type. File names retain path components; do not use multipart.Part.FileName's path stripping. Named selection rejects duplicates and recognizes only `form-data` dispositions; explicit ordinals can address other raw parts. Remove of text/file deletes the selected part; filename/type removal deletes that attribute/header while retaining content. Text set may add an absent text part; file-content set requires an existing file part. Filename set may add a file placeholder for subsequent content binding. Append/prepend combine text or decoded file bytes, never base64 strings. Null and numeric arithmetic remain JSON-only; file content operands/bindings must be base64 strings and cannot use binding prefix.

Parse bounded raw bodies using the original outer boundary and MIME headers. Support canonical CRLF framing, preamble/epilogue, opaque binary content, and at most 1,000 parts / 16 MiB total. Require one outer Content-Type, a valid form-data boundary, and identity outer Content-Encoding. Preserve untouched raw part headers/content/order and delimiter suffixes. Reject ambiguous Content-Disposition metadata; reject unsupported encodings when selecting content. Mutating headers must not allow control-byte injection. If new content collides with the boundary, choose a deterministic collision-free boundary and update the outer Content-Type before signing.

Static preflight validates multipart structure without clients. Runtime edits reparse/postvalidate the result and apply atomically. Current-value rendering returns text/metadata or base64 file content. Proof selects the actual sent part/attribute and compares exact values/bytes, accounting for deletion. Ordinal whole-part deletion compares the entire resulting body because later indices shift. Missing bodies, malformed structure, ambiguous names, changed encodings, or overwritten values are inconclusive.

HAR inference matches eligible unique prior scalar values to unique text parts, filenames, media types, and base64 file data. Preserve current thresholds and no-guess ambiguity behavior. Params-only multipart remains unreplayable because file bytes are unavailable. Binary bodies can be supplied through raw project request files; a HAR text field is treated as its supplied UTF-8 bytes without claiming to recover absent binary wire data.

## Script and authoring integration

Expose mutable request `bodyBase64` alongside `body` (null for non-UTF-8 bodies); response bodyBase64 is read-only and body is null for binary. Preserve bytes when unchanged. Accept one changed representation, or two consistent edits; reject conflicting/deleted/invalid representations atomically. Add `crypto.sha256Bytes(base64Data)` and `hmacSha256Bytes(base64Key, base64Data)`, with hexadecimal output. Existing string helpers stay compatible.

Expose the four locations in CLI help and the visual editor, including file byte representations and prefix constraints. Normal multipart evidence remains opaque/hash-only; sensitive traces retain exact bytes. Update examples and docs without adding target execution to the map.

## Proof and delivery

Tests must exercise raw-byte preservation, file metadata, base64 append/prepend, boundary collision handling, duplicates/malformed/unsupported encodings, and real observed multipart requests. Sign final binary bodies through JavaScript and verify server-side, including atomic failures. Generate/import an actual multipart capture, run cases and downstream checks with fresh state, reconstruct a selected case, and validate source drift/budgets. Include browser authoring/export and existing gates. Review and CI precede integration; then audit the full operator goal rather than expanding the backlog indefinitely.
