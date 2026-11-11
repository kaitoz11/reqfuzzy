# 14 — Testing Strategy

**Status:** stub
**Depends on:** D2 (seed), D17 (runtime/pins)
**Supersedes:** Section 10 of the single-document spec

## Purpose

Define how each engine component is verified, how payintv3 behavior is ported, and how the
agent contract is protected from drift.

## Required content

### 1. Test layers
- [ ] Unit per module (parser round-trip, DSL, matchers, plan, profiles, hooks, flows).
- [ ] Golden/contract tests (corpus load, plan determinism under seed, JSON schemas, exit
      codes).
- [ ] E2E against a local mock target.
- [ ] Agent-loop test (drives CLI exactly as `AGENT.md`).

### 2. Fixtures & determinism
- [ ] Fixed `--seed` for any test touching random DSL; otherwise assert structure/IDs only.
- [ ] Fixture layout (`tests/fixtures/...`) and how fixtures are regenerated.

### 3. ported payintv3 tests (do before engine code)
- [ ] `test_scripts/unit_test/test_dsl_parser.py`
- [ ] `test_scripts/unit_test/variable_processor_test.py`
- [ ] `test_scripts/unit_test/value_processor_test.py`
- [ ] `test_scripts/unit_test/parse_template_test.py`
- [ ] `test_scripts/unit_test/scan_payload_test.py`
- [ ] `test_scripts/test_output/test_matchers.py`
- [ ] Corpus-wide load test for all scan + matcher templates.

### 4. Mock target
- [ ] `tests/mock_target/` with deterministic vulnerable endpoints (SQLi error, boolean,
      time-based with short delay, SSTI, SSRF echo, reflected XSS).
- [ ] Time-based endpoint must not sleep real production durations; expose
      `sleep_time` override.
- [ ] OOB test double (local DNS/HTTP sink) if D1 = OOB-in-v1.

### 5. Agent contract protection
- [ ] Validate every `--json` output against its JSON Schema.
- [ ] "Docs drift" test: `AGENT.md` examples must execute.
- [ ] Exit-code matrix test.

### 6. Adversarial/robustness
- [ ] Fuzz the raw parser and DSL; malformed templates; corrupt run files.
- [ ] CI matrix (Python version from D17); no internet required.

### 7. Coverage & quality gates
- [ ] Coverage threshold, lint/type-check (ruff/mypy), import-direction test (see `02`).

## Interfaces / artifacts
- [ ] Test plan mapping: sub-spec → test file(s).

## DoD

- Every sub-spec has at least one named test file.
- E2E runs fully offline in CI.

## TODO

- [ ] Resolve D2, D17.
- [ ] Decide whether to port payintv3 tests verbatim or rewrite against new interfaces.
