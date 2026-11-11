# 15 — Packaging, Dependencies, Errors & Logging

**Status:** stub
**Depends on:** D13 (parser), D17 (runtime/pins), D19 (severity), D24 (versioning)
**Supersedes:** Section 11 (partially) and the deliverables note (Section 13)

## Purpose

Define the installable artifact, dependency policy, error taxonomy, and logging so behavior is
reproducible and failures are machine-readable.

## Required content

### 1. Packaging
- [ ] `pyproject.toml`: project metadata, entry point `kvar`, package data (`templates/`),
      optional extras (`watch`, `dev`).
- [ ] Python version (D17) and supported platforms.
- [ ] Lockfile / reproducible install; dependency update policy.

### 2. Dependencies
- [ ] Core: `httpx`, `pyyaml`, `typer`, `flatdict`, plus parser dep (D13).
- [ ] Detection-critical: `jellyfish`, `deepdiff` — **exact pins** (diff scores affect
      findings).
- [ ] Optional: `mitmproxy` (watch), others.
- [ ] Justify or drop `dpkt` (raw parser dependency in payintv3).

### 3. Error taxonomy
- [ ] Stable error codes/units: `raw_request.parse`, `template.load`,
      `template.unsupported`, `plan.build`, `profile.refresh`, `hook.load`, `flow.step`,
      `http.transport`, `http.timeout`, `authz.blocked`, `scope.blocked`, `run.corrupt`.
- [ ] Where each is raised, human format, JSON format, exit-code mapping.
- [ ] Partial-failure semantics (which errors are fail-stop vs recorded-and-continue).

### 4. JSON error schema
- [ ] `{ok:false, error:{code, unit, message, details, hint?}}` and exit code.

### 5. Logging
- [ ] Levels (`--verbose` mapping), destinations (stderr + run log file).
- [ ] HTTP trace/replay for debugging false positives (payintv3 `LogLauncher` parity).
- [ ] Secret redaction in logs (cross-ref `08`, `11`).

### 6. Versioning
- [ ] `kvar --version`; template `schema_version`; run `format_version` (D24).

## Interfaces / artifacts
- [ ] `KvarError` base + subclasses; error code registry.
- [ ] Logging bootstrap + log file format.

## DoD

- Every failure in `11`/`13` examples maps to a code in the registry.
- CI builds a wheel and runs `kvar --version` and `kvar explain topics` from it.

## TODO

- [ ] Resolve D13, D17, D19, D24.
- [ ] Decide whether `dpkt` stays.
