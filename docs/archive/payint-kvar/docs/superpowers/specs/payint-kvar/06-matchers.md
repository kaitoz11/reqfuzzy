# 06 — Matcher Semantics

**Status:** stub
**Depends on:** D3 (compat), D21 (timeout)
**Supersedes:** Section 5.5 of the single-document spec

## Purpose

Define how a response becomes a finding: matcher types, condition evaluation, ref-merge,
diff algorithms, and timeout handling.

## Required content

### 1. Matcher types
- [ ] `dsl` (list sorted — confirm and document ordering effect).
- [ ] `status`.
- [ ] `word` (`part: header|body`).
- [ ] For each: exact evaluation, short-circuit behavior, and what the finding records.

### 2. Condition semantics
- [ ] `matcher_condition: and|or` truth table across matchers.
- [ ] Interaction with matcher-ref-merged matchers (one condition for all, per payintv3).
- [ ] Which matcher/expression index is recorded; behavior when AND succeeds with no single
      matcher.
- [ ] Empty matcher list behavior.

### 3. Response variables
- [ ] `content_length`, `status_code`, `headers`, `body`, `response_time`, `raw_request`.
- [ ] Header serialization format (`\r\n` join — exact).
- [ ] Text decoding/charset policy (cross-ref `03`).

### 4. Diff algorithms
- [ ] Text similarity: exact algorithm (jaro-winkler) **and pinned dependency version**.
- [ ] JSON diff: `deepdiff` config, checked keys (`added`/`removed`/`values_changed`/
      `type_changes`), ordering.
- [ ] Threshold defaults (`levenshtein_distance` / `diff_text_ratio_constant = 0.05`) and
      per-test-case overrides.
- [ ] Baseline required vs absent behavior (skip + log; no finding).

### 5. Timeout / transport-failure matching
- [ ] How a synthetic timeout response is represented (D21) so `response_time` matchers work.
- [ ] Distinguish `not_sent`, `timeout`, and real HTTP error statuses.

### 6. False-positive controls
- [ ] Baseline guards, minimum body length, identical-status handling.
- [ ] Documented false-positive test cases.

## Interfaces / artifacts
- [ ] `evaluate_matchers(response, matchers, condition, context) -> MatchResult`
- [ ] `MatchResult{matched, matcher, expression_index, diff_ratio, confidence}`

## DoD

- Truth table present; diff algorithm + version pinned; timeout path defined.
- Golden matcher tests ported from `payintv3/test_scripts/test_output/test_matchers.py`.

## TODO

- [ ] Resolve D21; define `confidence`.
