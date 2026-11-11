# 04 — Template Schema & Action Catalog

**Status:** stub
**Depends on:** D3 (compat scope), D5 (override), D10/D23 (safety), D25 (concurrency)
**Supersedes:** Sections 5.2 and 5.3 (partial) of the single-document spec

## Purpose

Define every template field, every action's mutation semantics, every value type, matcher-ref
resolution, and versioning. "Corpus ports unchanged" becomes a testable contract here.

## Required content

### 1. Template envelope
- [ ] `id`, `info{name, author, description, tags, severity, references, cwe?, owasp?,
      remediation?}`, `type`, `schema_version`.
- [ ] Required vs optional fields; validation errors and messages.
- [ ] `safety: safe|aggressive|destructive` (D23) and `concurrency: safe|not_safe` (D25).
- [ ] `skip_current_parameter_if_match`.
- [ ] Tag indexing and `--tags` semantics (union/OR, confirmed).
- [ ] Overlay/override rules (D5) and duplicate-id reporting.

### 2. Scan template body
- [ ] `variables` (defaults + template + project merge order; `nfc` handling; derived vars
      like `sleep_time_mil_secs`).
- [ ] `test_cases[]`:
  - [ ] `values`, `value_type` (all 11: int/float/bytes/str/bool/dict/list/one_string/
        big_number/repeat_str/reserved_string) with processing rules.
  - [ ] `actions[]` — full catalog below.
  - [ ] `create_custom_request_info` (control request) and special index `-1`.
  - [ ] `matchers[]`, `matcher_condition`, `matcher_template_ref_tags`.
  - [ ] `levenshtein_distance`.

### 3. Action catalog (each needs exact semantics + examples)
- [ ] `prepend`, `append`, `replace`, `overwrite`
- [ ] `remove`
- [ ] `add_number_to_base`, `multiply_number_to_base`
- [ ] `json_transform` (+ special keys `__overwrite__`, `__overwrite_dict__`,
      `__update_root__`)
- [ ] `parameter_pollution`
- [ ] `traverse_update_json`
- [ ] For each: return shape (single dict vs multi dict), key targeting, base-value handling,
      error behavior.

### 4. Value processing
- [ ] `repeat_str` `$$` syntax and edge cases.
- [ ] `big_number` / `reserved_string` / parameter-pollution prefix markers and unwrap timing.
- [ ] `dict`/`list` literal parsing and type preservation.
- [ ] `one_string` newline stripping.

### 5. Matcher templates
- [ ] Matcher template schema (`id`, `info`, `type: matcher`, `matchers[]`,
      `matcher_condition`).
- [ ] `matcher_template_ref_tags` resolution: when (load time), ordering, and merge semantics
      (payintv3 `list.extend`).

### 6. Corpus compatibility matrix
- [ ] A table of every built-in template (60 scan + 30 matcher) with `supported | partial |
      unsupported` and the reason.
- [ ] Loader behavior on unsupported templates: fail loudly, never silent `None`.

## Interfaces / artifacts
- [ ] Pydantic/JSON-Schema models for scan + matcher templates.
- [ ] `load_templates(paths) -> TemplateSet` with deterministic ordering.
- [ ] Corpus load test (all files load, all supported ones expand).

## DoD

- Every template in the corpus is classified; no silent skips.
- A new template author can write a valid template from this doc + `kvar explain templates`.

## TODO

- [ ] Resolve D3; fill the compatibility matrix.
- [ ] Decide schema_version grammar and migration policy.
