# 10 — CLI Contract

**Status:** stub
**Depends on:** D8 (authz), D15 (export), D20 (control visibility)
**Supersedes:** Section 4 of the single-document spec

## Purpose

Define every command's arguments, defaults, behavior, exit code, and **exact `--json`
schema**. This is the machine contract agents depend on.

## Required content

### 1. Global conventions
- [ ] `--project DIR` discovery (walk up? explicit only?), path resolution rules.
- [ ] `--json` envelope: one document, versioned, `{ok, version, command, data, error?}`.
- [ ] stdout/stderr split: results on stdout, progress/logs on stderr.
- [ ] Exit codes and **precedence** (e.g. findings + partial transport failure).
- [ ] `--verbose` levels; `--quiet`.
- [ ] Config precedence (CLI > env > project config > defaults).

### 2. Per-command contract (each: args, defaults, behavior, JSON schema, exit codes)
- [ ] `init [DIR]` — scaffold contents, `.gitignore`, authorization gate default.
- [ ] `show request <file>`
- [ ] `show params <file>` — what counts as attackable; default header exclude list.
- [ ] `show templates [--tags] [--search]`
- [ ] `show template <id>`
- [ ] `show profiles [--redact]`
- [ ] `explain <topic>` / `explain topics` — generated content source.
- [ ] `scan` — `--params` syntax and precedence vs `--all-params`/`--exclude`; `--set`;
      `--flow`; `--resume`; `--plan`; `--max-requests`; `--timeout`; `--proxy`/
      `--scan-proxy`; `--insecure`; `--seed`; `--authorized`; `--allow-destructive`;
      `--tags`; scan envelope schema.
- [ ] `send` — applies profile + `before_send`? requires authz?
- [ ] `import` — positional vs `--watch`, filters, `--infer-flows`.
- [ ] `requests list` / `requests show`
- [ ] `flow run`
- [ ] `flows show` / `flows suggest`
- [ ] `findings [--id] [--run] [--json]` and `findings export --format jsonl|md` (D15).

### 3. Finding JSON (contract)
- [ ] Finalize fields: `id`, `template_id`, `tags`, `severity`, `confidence`, `location`,
      `parameter`, `payload_as_sent`, `matched_rule`, `evidence`, `run_id`, `seq_id`.
- [ ] Dedup representation (D11).
- [ ] Evidence pointer format and file naming.

### 4. Scan envelope JSON (contract)
- [ ] Exact nested schema for `{request, profile, flow_vars, plan_summary, requests_sent,
      findings[], artifacts_dir, scan_state}`.

## Interfaces / artifacts
- [ ] JSON Schema for every `--json` output.
- [ ] An `AGENT.md` generated/validated from these schemas.
- [ ] Agent-loop tests drive exactly these shapes (cross-ref `14`).

## DoD

- Every command documented with a copy-pasteable `--json` example.
- `kvar explain` topics and this doc share one source of truth.

## TODO

- [ ] Resolve D8, D15, D20.
- [ ] Decide `send` authorization requirement.
