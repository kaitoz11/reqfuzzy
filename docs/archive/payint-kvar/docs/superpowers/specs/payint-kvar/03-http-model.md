# 03 — HTTP Model & Raw Request Parser

**Status:** stub
**Depends on:** D6 (TLS)
**Supersedes:** Section 5.1 of the single-document spec
**Gates:** everything downstream.

## Purpose

Define the raw-request grammar, the immutable request model, the builder API, encoding rules,
and round-trip fidelity. This is the highest-leverage sub-spec: a wrong request model makes
every scan wrong.

## Required content

### 1. Raw request grammar
- [ ] EBNF for the accepted format (request line, headers, blank line, body).
- [ ] CRLF vs LF, header folding, whitespace, absent Host, HTTP version handling.
- [ ] Content-Length sanitization (payintv3 removes it before re-encoding).
- [ ] Duplicate headers, header case, header order preservation.
- [ ] Chunked `Transfer-Encoding` policy (reject? decode?).
- [ ] Body-less methods, GET with body, HEAD.
- [ ] Multipart: fields vs files, boundary, `filename*`, per-part content-type.
- [ ] Non-UTF-8 / binary bodies; charset in `Content-Type`.

### 2. Request model
- [ ] Immutable model fields: method, scheme, host, port, path segments, headers, query,
      cookies, body, files, content-type.
- [ ] Nested parameter path representation (flat delimiter `:`; arrays; bracket notation).
- [ ] Query parsing: repeated keys, arrays, percent-encoding.
- [ ] The complete builder API: every `.with_*()` method with signature and semantics
      (replace vs update-if-existing vs add).
- [ ] Equality / hashing semantics (for dedup and plan stability).

### 3. Encoding & content types
- [ ] Content-type set: JSON, URLENCODED, MULTIPART, XML, UNKNOWN, NONE (or a deliberate
      subset).
- [ ] Inference algorithm when `Content-Type` is absent/ambiguous.
- [ ] Encode/decode round-trip guarantees and where they can diverge.
- [ ] Special-prefix unwrap at send time (`PayIntBigNumber[...]`, `PayIntReservedStr[...]`,
      `PayIntPollution[...]`).

### 4. Send policy (HTTP client)
- [ ] TLS verify (D6), redirect policy, retries/backoff, connect/read/write timeouts,
      HTTP/1.1 vs HTTP/2, keep-alive, connection reuse.
- [ ] Proxy wiring (see D7 / `02`): normal vs scan client.
- [ ] Cookie jar behavior and how profile cookies interact (also in `08`).
- [ ] Response capture: raw bytes, decoded text, status, headers, elapsed time.

### 5. Fidelity evidence
- [ ] Byte-level round-trip test vectors (Burp paste, CRLF, duplicate headers, multipart,
      binary, no-CRLF, folded headers).
- [ ] Documented list of deliberate divergences from payintv3 `web/factory.py`.

## Interfaces / artifacts
- [ ] `parse_raw_request(bytes) -> HttpRequest`
- [ ] `HttpRequest` model + JSON representation
- [ ] `HttpClient.send(HttpRequest, policy) -> HttpResponse` (or pseudo-response for timeout,
      see D21)

## DoD

- EBNF + test vectors + builder API signatures are all present.
- Every divergence from payintv3 is explicit.
- Round-trip tests pass on the vector corpus.

## TODO

- [ ] Decide chunked/TE policy.
- [ ] Decide XML handling in or out of v1.
- [ ] Resolve D6, D7, D21.
