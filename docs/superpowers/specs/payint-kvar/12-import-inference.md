# 12 — Traffic Import & Flow Inference

**Status:** stub
**Depends on:** D12 (inference sources), D14 (watch)
**Supersedes:** Section 8 of the single-document spec

## Purpose

Define capture ingestion (HAR / mitmproxy / raw), the `--watch` mode, stable naming, and the
flow-inference algorithm.

## Required content

### 1. Sources
- [ ] HAR: supported version(s), entries with/without responses, cookies, `postData` mime
      types, base64 bodies.
- [ ] mitmproxy flow dump: format/version handling; clarify that `.mitm` is a dump file.
- [ ] Raw request directory: accepted layout.
- [ ] `--watch`: transport (D14), address/port semantics (proxy port, not bind address),
      lifecycle/shutdown.

### 2. Normalization
- [ ] Every entry → raw request file in `requests/`; naming
      `<seq>_<METHOD>_<host><path>.txt`, sanitization, collision counter.
- [ ] Stable across re-imports (idempotency key = method+host+path+body hash?).
- [ ] Dedup key and behavior on collisions.
- [ ] Preserve cookies/auth (replayable) but warn on captured secrets (cross-ref `08`).
- [ ] Filters: `host:` / `path:` exact grammar (glob vs substring), multiple filters.
- [ ] Auto-drop rules: static assets, CONNECT noise (list the extensions/content types).

### 3. Inventory
- [ ] `requests list` columns; collapse rule (host+path+method, count), `--expand`.
- [ ] `requests show` output schema.

### 4. Flow inference
- [ ] Inputs restricted to response-bearing sources (D12); raw dirs rejected.
- [ ] Taint pass: which scalars, JSON depth, regex patterns, search locations
      (body/query/header/cookie/path).
- [ ] Match scoring: exact = high, encoded/normalized = lower; enumerate normalizers
      (URL, JSON, base64, hex?).
- [ ] False-positive filtering (booleans, 0/1, timestamps, generic ids).
- [ ] Output `flows/suggested-<name>.yaml` schema — must be directly consumable by `09`.
- [ ] Performance bounds (streaming, response size cap, top-K).
- [ ] Never auto-executed; review flow documented.

### 5. Agent loop
- [ ] navigate → import → inventory → infer → scan → findings, with exact commands and
      JSON handoffs.

## Interfaces / artifacts
- [ ] `import_traffic(source, options) -> ImportResult`
- [ ] `infer_flows(entries, options) -> list[SuggestedFlow]`
- [ ] Imported-request JSON schema; suggestion JSON schema.

## DoD

- A HAR fixture imports idempotently (same file names on re-import).
- An inference fixture produces a valid flow file that `kvar flow run` accepts.

## TODO

- [ ] Resolve D12, D14.
- [ ] Decide the `.mitm` ambiguity (file vs directory).
