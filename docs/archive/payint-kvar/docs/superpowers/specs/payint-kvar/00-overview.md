# 00 — Overview & Scope

**Status:** stub
**Depends on:** `01-decisions.md` (answers D1–D10)
**Supersedes:** Sections 1–2 and the roadmap of `../2026-09-27-payint-kvar-design.md`

## Purpose (fill in)

One paragraph: what kvar is, who it is for (agents + humans), what makes it different
(CLI-first, template-driven, ported corpus, machine-readable).

## Non-goals (fill in)

Explicitly out. Current candidates: IDOR, unauthentication, mass assignment, upload scans;
MCP server; concurrency; auto request construction flags (`--url/--method/--data`).

## Scope table (required)

A single table is the contract. Every capability must appear exactly once.

| Capability | v1 | v2 | Notes | Blocked by |
|------------|----|----|-------|-----------|
| Raw request scan | ✅ | | | |
| SQLi (error/boolean/time/DNS) | ? | | OOB split — see D1 | D1 |
| NoSQLi / SSTI / CMDi | ? | | | |
| SSRF / log4j / CVE families | ? | | OOB split — see D1 | D1 |
| XSS | ? | | OOB/browser split — see D1 | D1 |
| Fuzz / finance / email families | ? | | | |
| DoS / destructive families | ? | | gate — see D10 | D10 |
| Path traversal / XXE | ? | | | |
| Auth profiles + hooks | ✅ | | | D18, D22 |
| Flows (prepare steps) | ✅ | | | |
| HAR / mitmproxy / raw import | ✅ | | | D14 |
| Live `--watch` capture | ? | | | D14 |
| Flow inference | ✅ | | response-bearing sources only | D12 |
| OOB interaction server | ? | | | D1 |
| Concurrency | ❌ | ✅ | schema placeholder now | D25 |
| IDOR / unauthen / mass-assignment / upload | ❌ | ✅ | | |
| MCP server | ❌ | ✅ | | |

## Positioning rules (fill in)

- Authorized testing only; see `13-safety-authz.md`.
- No sample-project copying; project dir is data only.
- Engine is importable; CLI is a thin shell.
- Templates are data, not code.

## Required content

- [ ] Scope table completed for every capability, with v1/v2 and blockers.
- [ ] "Deferred to v2" list matches the scope table exactly (no drift).
- [ ] Success criteria for v1 (what proves it works end-to-end).
- [ ] One-paragraph non-technical summary suitable for `USAGE.md`/`AGENT.md`.
- [ ] Relationship to payintv3 restated once (what is ported, what is rewritten, what breaks).

## DoD

- An executor can answer "is X in v1?" from the scope table alone.
- No capability is both "in scope" and "detection deferred" without an explicit
  `confidence`/`unconfirmed` note (see D1).

## TODO

- [ ] Resolve D1 (OOB) before filling the SQLi/SSRF/XSS rows.
- [ ] Resolve D10 before filling the DoS row.
