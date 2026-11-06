# Reusable payload sets and templates

Campaigns can combine explicit `cases` with ordered `payloads` sources. Inspect an expanded campaign offline before running it:

```sh
bin/reqfuzzy flow plan --project examples/session-recovery --test payload-tests.yaml --json
```

The plan reports case IDs, actions, source/index metadata, input count, and the maximum baseline-plus-cases request count. It sends no requests and executes no hook code. `within_budget: false` keeps an oversized plan inspectable; `flow test` still refuses execution unless the explicit budget permits it. Use `--hooks` when scripts live in an explicitly selected directory.

## Typed lists, files, and ranges

```yaml
payloads:
  - {id: types, action: set, values: [-1, 0, null, true, "NaN"]}
  - {id: probes, action: append, file: payloads/probes.txt}
  - {id: exact-ids, action: set, range: {from: 9007199254740993, to: 9007199254740995}}
  - {id: removal, action: remove}
```

Untransformed values retain their JSON scalar type and exact number text. A source needs exactly one of `values`, `file`, or `range`; remove takes none. Existing set/remove/append/prepend rules still apply to the selected location.

File paths are relative to the project. `format: lines` (default) treats each UTF-8 line as a literal string, preserves internal empty lines, strips CRLF line endings, and adds no phantom value after a terminal newline. Comments and template-looking text stay literal. `format: jsonl` requires one JSON scalar on each line, so numbers, booleans, null, and strings remain distinct. Empty/invalid JSONL records are errors.

Ranges use inclusive decimal integer endpoints and an exact integer step, default 1. Descending ranges need a negative step. Zero/wrong-direction steps and excessive counts are rejected before generation; large IDs never pass through float64.

Explicit cases precede sources; source and value declaration order is preserved. IDs use `source-000001` with the original one-based index. `unique: true` skips byte-identical typed values without renumbering later IDs. Numbers `1` and `1.0`, and string `"1"`, remain distinct. Namespaces must be unique safe IDs up to 56 characters; case-ID collisions are errors.

Definitions/files are bounded to 8 MiB, source input entries and total expanded cases to 10,000, aggregate expanded value/render definitions to 64 MiB, and encoder pipelines to 16 stages. Rendered/encoded output is bounded to 8 MiB per value. Compiled cases retain lazy render operations rather than expanded payload copies.

## Shared library files

In the campaign:

```yaml
payloads:
  - {id: finance, use: payloads/finance.yaml}
```

`payloads/finance.yaml`:

```yaml
version: 1
action: multiply
file: operators.jsonl
format: jsonl
unique: true
```

`operators.jsonl` resides beside that library and contains numeric records such as `-1`, `0`, and `2`. A library has the same source fields except `id`/`use`; its namespace comes from the campaign. Library references cannot override fields or recursively import libraries. Files and symlinks must remain inside the project. Every library and wordlist participates in replay input fingerprints.

## Fresh-state rendering and encoding

```yaml
payloads:
  - id: probes
    action: set
    file: payloads/probes.txt
    render: "{{value}}:{{var:nonce}}"
    encode: [base64]
```

The available placeholders are `{{value}}` (this source's value), `{{base}}` (the selected request scalar after bindings), and `{{var:name}}` (a flow variable declared before the target). Missing runtime variables/base fields fail before sending that target. Substitution is single-pass: inserted text containing `{{...}}` is data, not another expression.

Ordered encoders are `url` (query-style escaping), `base64`, `hex`, and `json` (JSON string representation). Rendering or encoding produces a string; it does not convert rendered text back into a number or execute code. Null/non-string encoder declarations are rejected. The request location performs its normal transport encoding afterward, so an explicit URL encoding can intentionally yield double encoding.

Templates are evaluated on each target visit, after current state is bound and before final signing. In the recovery example, a nonce-based encoded probe therefore changes after refresh. Proof compares each resulting sent mutation normally. The map protects payload-only variable dependencies when their producers are edited or removed.

## Exact base-value arithmetic

`add` and `multiply` operate on an existing JSON number using a numeric operand:

```yaml
cases:
  - {id: increment, action: add, value: 0.2}
  - {id: negative, action: multiply, value: -1}
```

For example, `0.1 + 0.2` becomes `0.3`, and multiplying ID `9007199254740993` by −1 preserves all digits. Arithmetic uses the current bound value on every visit. String/null/object targets and non-JSON locations are rejected; string rendering/encoding cannot be combined with arithmetic. Number text/results are limited to 4096 characters and supported exponents to ±10000. Zero is normalized to `0`; literal signed-zero fuzzing remains available with `set`.

## Run and reconstruct a generated case

Start the existing reference API with `--refresh-once --vulnerable-amounts`, then:

```sh
bin/reqfuzzy flow test --project examples/session-recovery --test payload-tests.yaml --base-url http://127.0.0.1:8098 --out .reqfuzzy/generated-finance --json
bin/reqfuzzy flow replay --project examples/session-recovery --base-url http://127.0.0.1:8098 --run .reqfuzzy/generated-finance --case finance-000001 --out .reqfuzzy/generated-replay --json
```

The generated negative multiplier reproduces balance 110 with mutation proof across both signed attempts. Use `text-payload-tests.yaml` to exercise literal wordlists and nonce-based encoding. Changed source bytes refuse reconstruction before traffic. Recipes and normal summaries retain IDs/origins/hashes, not payload or render text.
