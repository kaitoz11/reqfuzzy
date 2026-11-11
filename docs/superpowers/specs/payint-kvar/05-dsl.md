# 05 — DSL Specification

**Status:** stub
**Depends on:** D2 (determinism), D3 (compat), D13 (parser)
**Supersedes:** Sections 5.3 and 9 (dsl topic) of the single-document spec

## Purpose

Define the expression language used in templates and matchers precisely enough to port or
rewrite it without semantic drift.

## Required content

### 1. Grammar
- [ ] EBNF: literals, function calls, comparisons (`< <= > >= <> ==`), boolean `and`/`or`/`!`,
      parentheses, precedence, associativity.
- [ ] String literal syntax (payintv3 uses **doubled quotes** `""...""`; document exactly).
- [ ] Special constants `[EMPTY]`, `[DOUBLE_QUOTES]`.
- [ ] Number types (int/float), booleans, truthiness.
- [ ] Whitespace/comment behavior.

### 2. Function catalog
- [ ] Every generator: `rand_base`, `rand_token`, `rand_number_range`, `rand_uppercase`.
- [ ] Every transformer: `sha256`, `b64_encode`, `b64_decode`, `b64_replace`, `urlencode`,
      `unhexlify`, `insert_chars_to`, `replace_str`, `reversed_str`.
- [ ] Every predicate: `contains`, `contains_all`, `contains_any`, `contains_regex`.
- [ ] Matcher-only helpers: `sql_detect_diff_response`, `idor_detect_diff_response`,
      `is_mass_assignment_vuln`.
- [ ] For each: signature, argument order (note the `functools.partial` quirk), types,
      return, errors, examples.

### 3. Variable vs expression evaluation
- [ ] Substitution order (top-down), recursion limits, unknown-variable behavior.
- [ ] When functions are evaluated (template load vs plan expansion) and what is recorded.
- [ ] `base_value` special variable semantics.
- [ ] Response variables (`current_response`, `base_response`, `*_object`,
      `current_test_case_value`, `current_test_case_parameter_name`) and where each is bound.

### 4. Compatibility stance
- [ ] Bug-for-bug vs cleaned-up (tie to D3/D13). List every known quirk and the chosen behavior.
- [ ] Escaping/quoting rules and an escaping test suite.

### 5. Error policy
- [ ] Missing variable, unsupported function, runtime error, no baseline: skip matcher, fail
      plan, or abort scan? Specify per context.

## Interfaces / artifacts
- [ ] `evaluate(expr, context) -> value`
- [ ] `expand_variables(template, context) -> resolved_template`
- [ ] `kvar explain dsl` content generated from the same source of truth as this doc.

## DoD

- Grammar + function catalog + examples are complete.
- Golden tests ported from `payintv3/test_scripts/unit_test/{test_dsl_parser,variable_processor_test,value_processor_test}.py`.
- `kvar explain dsl` is generated, not duplicated.

## TODO

- [ ] Resolve D13; if rewriting, define the divergence list.
