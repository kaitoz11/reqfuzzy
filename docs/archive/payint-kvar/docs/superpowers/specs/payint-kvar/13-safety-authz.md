# 13 — Safety, Authorization & Scope

**Status:** stub
**Depends on:** D1 (OOB), D8 (gate), D9 (scope), D10/D23 (danger)
**Supersedes:** the authorization note in Sections 1 and 9, and the roadmap safety items

## Purpose

Define the controls that make an offensive tool defensible: authorization gate, host scope,
destructive-template gating, rate/budget limits, and the OOB stance.

## Required content

### 1. Authorization gate
- [ ] Which commands require it (D8); offline commands exempted.
- [ ] Persisted `authorized: true` vs per-run `--authorized`; prompt behavior in a TTY vs
      non-interactive; exact error + exit code when blocked.

### 2. Scope allowlist
- [ ] `scope: [patterns]` schema (glob/wildcard semantics), enforced at send time.
- [ ] Out-of-scope target → refusal (not a silent skip) with the offending host.
- [ ] Interaction with imported HAR (third-party hosts) and flow redirects.
- [ ] `config.yaml` `scope` vs CLI `--scope` override.

### 3. Destructive-template gating
- [ ] `safety` values (D23) and the default policy (exclude unless `--allow-destructive`).
- [ ] `--plan` warns and counts destructive payloads.
- [ ] Rate limit and request budget for aggressive families.

### 4. Rate limiting / budget
- [ ] `--delay`, `--rate`, retry/backoff, global request cap; per-host vs global.
- [ ] How limits interact with resume and flows.

### 5. OOB stance
- [ ] Restate D1 outcome: whether an interaction server exists, or OOB findings are
      `unconfirmed`; the finding `confidence` contract.
- [ ] If OOB in v1: interaction-server configuration, polling, and timeout model.

### 6. Legal / UX wording
- [ ] The consent text in `AGENT.md` / `USAGE.md` and `kvar init`.

## Interfaces / artifacts
- [ ] `AuthzCheck` + `ScopeCheck` APIs used by the send loop.
- [ ] `safety` enum shared with `04`.

## DoD

- A test proves an out-of-scope host is refused.
- A test proves destructive templates do not run without the flag.
- The OOB behavior is unambiguous in code and docs.

## TODO

- [ ] Resolve D1, D8, D9, D10, D23.
