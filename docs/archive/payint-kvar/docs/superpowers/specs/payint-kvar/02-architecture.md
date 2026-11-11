# 02 — Architecture & Project Layout

**Status:** stub
**Depends on:** D7 (proxy), D13 (parser), D16 (sync/async)
**Supersedes:** Section 3 of the single-document spec

## Purpose

Define the package layout, the one-way dependency rule, module responsibilities, extension
points, and the concurrency model. This is the map an executor uses to place code.

## Required content

### 1. Package layout (complete, not illustrative)
- [ ] Full tree including modules missing from the original spec: `config`, `errors`,
      `logging`, `state`, `run_store`, `authz`/`scope`, `importers/`, `flows/`.
- [ ] Decide `engine/` vs top-level split for `profiles.py`/`hooks.py` (currently inconsistent).
- [ ] Data packaging: where built-in `templates/` live, how they are installed, how
      `custom_templates/` overlays them.
- [ ] `kvar_skill/` location and how it ships.

### 2. Dependency direction
- [ ] `cli → engine → (http, templates, storage)`; engine never imports CLI.
- [ ] Every module list: imports allowed and forbidden.
- [ ] A test/lint rule that enforces the direction (import-linter or a unit test).

### 3. Module responsibilities (one line each)
- [ ] `raw_request.py` — parse raw file → `HttpRequest`.
- [ ] `http_model.py` — immutable request model + builder API.
- [ ] `http_client.py` — send with proxy/TLS/retry/timeout policy.
- [ ] `templates/` loader — discover, validate, index by id/tag, resolve matcher refs.
- [ ] `payloads.py` — plan generation (see `07-payload-plan.md`).
- [ ] `dsl.py` — expression engine (see `05-dsl.md`).
- [ ] `matchers.py` — evaluation (see `06-matchers.md`).
- [ ] `findings.py` — finding model, dedup, serialization.
- [ ] `run_store.py` — run dirs, plan/state/findings persistence, resume.
- [ ] `flows.py` — flow execution + extraction.
- [ ] `importers/` — HAR / mitmproxy / raw.
- [ ] `inference.py` — flow suggestion.
- [ ] `config.py` — load/merge config, precedence.
- [ ] `authz.py` — authorization gate + scope allowlist.
- [ ] `errors.py`, `logging.py` — taxonomy + verbosity.

### 4. Concurrency model (freeze now)
- [ ] Sync vs async decision (D16) and the **scheduler interface** that makes v2 workers
      additive.
- [ ] How time-based families are kept strictly sequential.
- [ ] Cancellation / `--max-requests` / interrupt (SIGINT) behavior.

### 5. Extension points
- [ ] Hooks (see `08-auth-hooks.md`), custom templates, custom importers? — enumerate exactly.
- [ ] Public Python API surface (`kvar.engine` exports) promised as stable.

### 6. Data-flow diagrams (required)
- [ ] scan: parse → plan → (baseline/control) → send → match → finding → artifacts.
- [ ] flow: steps → extract → vars → scan injection.
- [ ] import: source → normalize → `requests/` → inventory → inference.

### 7. Interfaces / artifacts
- [ ] Function/class signature stubs at every module boundary (the executor's contract).
- [ ] List of schemas owned by this sub-spec (none; it references others).

## DoD

- An executor can create every file/package from the tree and know its single responsibility.
- No module has an undocumented import.
- The scheduler interface exists even though v1 runs one worker.

## TODO

- [ ] Resolve D16 before writing §4.
- [ ] Reconcile the original spec's `engine/profiles.py`/`hooks.py` placement.
