# 11 — Run Artifacts, State Store & Findings

**Status:** stub
**Depends on:** D4 (resume), D11 (dedup), D24 (versioning)
**Supersedes:** Sections 5.6 and 4 (`runs/`, resume) of the single-document spec

## Purpose

Define exactly what is written to disk for each run, the schemas, redaction, resume support,
and run discovery.

## Required content

### 1. Run directory layout
- [ ] `runs/<run_id>/` tree (deterministic `run_id`; timestamp + optional `--run-id`).
- [ ] Files: `run.json`, `plan.json`, `scan_state.json`, `findings.json`, evidence dir,
      request/response files, logs, flow outputs.
- [ ] Naming and correlation: `seq_id` → evidence files (the finding example's `req_0007.txt`
      must map to a plan entry).
- [ ] Encode/preserve request bytes; response size cap and truncation marker.
- [ ] `.gitignore` for `runs/`.

### 2. Run metadata (`run.json`)
- [ ] `format_version`, kvar version, timestamps, project, target scope, profile, seed,
      template hashes, request-file hash, config snapshot.

### 3. Plan & state
- [ ] `plan.json` (resolved plan; shared with `07`).
- [ ] `scan_state.json` cursor + `not_sent` set + counters.

### 4. Findings
- [ ] `findings.json` schema (shared with `10`).
- [ ] Finding dedup key (D11) and how multiple triggering payloads are grouped.
- [ ] Confidence values (`confirmed | unconfirmed | timeout-observed`) from D1/D21.
- [ ] Evidence pointers (request/response/control files).

### 5. Redaction & retention
- [ ] Never persist resolved credentials; redact auth headers/cookies in stored requests
      (configurable `--keep-secrets` for debugging?).
- [ ] Log file contents and verbosity.
- [ ] Retention/rotation policy (manual vs auto).

### 6. Discovery
- [ ] `runs` index / manifest so `findings --run` and `--resume` can find runs.
- [ ] Behavior on partial/corrupt runs.

## Interfaces / artifacts
- [ ] `RunStore` API: `create`, `write_plan`, `write_state`, `write_finding`,
      `load_run`, `list_runs`.
- [ ] JSON Schemas for all run files.

## DoD

- A run can be resumed and inspected after a hard kill with no data loss.
- Redaction test proves secrets never appear in `runs/`.

## TODO

- [ ] Resolve D4, D11, D24.
- [ ] Decide evidence truncation threshold.
