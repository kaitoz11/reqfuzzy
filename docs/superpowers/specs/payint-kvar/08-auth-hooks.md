# 08 — Auth Profiles, Secrets & Hooks

**Status:** stub
**Depends on:** D18 (secrets), D22 (hook set)
**Supersedes:** Section 6 of the single-document spec

## Purpose

Define how identities are declared and injected, how secrets are stored/resolved/redacted, and
the exact hook contract.

## Required content

### 1. Profile schema
- [ ] Exact YAML schema (`name`, `description`, `credentials`, `credentials_from`, `inject`,
      `hooks`).
- [ ] Injection locations: headers, cookies, body, query, files.
- [ ] Nested body/query path syntax.
- [ ] Overwrite-if-present vs add-if-absent rules (payintv3 has distinct builder methods).
- [ ] Interaction with existing raw-request auth; multiple profiles (attacker/victim) schema.
- [ ] Interpolation template syntax and escaping.

### 2. Secrets
- [ ] `profiles/secrets.yaml` reference syntax (`#anchor`).
- [ ] Environment indirection (`${ENV:VAR}`) and precedence.
- [ ] `.gitignore` scaffolding by `kvar init`.
- [ ] Redaction in `show`, logs, and run evidence; warning on imported captured secrets.

### 3. Hook contract
- [ ] Discovery rules (file → function name), load order, import errors.
- [ ] `before_send(request, profile) -> request|None` — mutation, immutability, context.
- [ ] `refresh(profile, reason?) -> profile` — trigger conditions (401/403, flow failure),
      retry-count location (no infinite loops), propagation to in-flight scan and cookie jar.
- [ ] Whether `after_response`/`on_finding` are reserved for v2 (D22).
- [ ] Error policy: fail loudly with traceback (confirm abort scope: request vs run).
- [ ] What the context object exposes (run, flow vars, seq_id).
- [ ] Per-request nonce/CSRF guidance.

### 4. Cookie/session behavior (shared with `03`)
- [ ] One client/jar per profile; Set-Cookie propagation across flow steps and scan requests.
- [ ] Cross-host cookie rules.

## Interfaces / artifacts
- [ ] Profile Pydantic model.
- [ ] `apply_profile(request, profile) -> HttpRequest`
- [ ] `run_hook(event, ...)` + hook execution result type.
- [ ] `kvar explain writing-hooks` generated from this doc.

## DoD

- `kvar show profiles` output schema defined; redaction verified by test.
- Hook failure tests (exception, bad signature, missing function) all produce clear errors.

## TODO

- [ ] Resolve D18, D22.
- [ ] Decide if `refresh` needs response context.
