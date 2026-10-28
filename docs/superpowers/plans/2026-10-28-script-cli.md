# Script Hooks and CLI Implementation Plan

> Execute inline with `superpowers:executing-plans`; use focused failing behavior tests before implementation, and the requesting-code-review skill before delivery.

Goal: make the existing reqfuzzy flow engine usable from a command and synchronous JavaScript hooks.

Spec: `docs/superpowers/specs/2026-10-28-script-cli-design.md`.

## Tasks

- [x] Extend flow steps with `after_response`/`provides`, validate references, preflight hooks, record provided values, and preserve existing execution behavior. Add a global preparation callback and shared set-mutation constructor. Test response-script handoff and failures against a local server.
- [x] Add `pkg/attacker/script` using pinned Goja: compile/check exports, isolated VM per call, deadlines/cancellation, staged request and variable edits, explicit scalar/raw APIs, crypto/encoding helpers. Test final-body signing, raw large numbers, malformed edits, exceptions, Promise returns, and infinite loops.
- [x] Add strict project manifests and atomic offline import under `internal/cli`. Select one origin, reject output conflicts, keep generated request paths within the project, and serialize the editable flow.
- [x] Add `cmd/reqfuzzy` and `internal/cli.Run` for import/show/run/compare, explicit target, hook loading, deadlines, safe summaries, JSON envelope, and documented exit codes. Test the real handler through the complete local journey, including a post-response script and signing after mutation.
- [x] Align README and the historical kvar notes with reqfuzzy as canonical; document scripts and commands with a runnable local example. Add CI for race tests, vet, and build.
- [x] Review the completed diff, address substantive findings, verify the final commit, and publish a draft PR against `feat/req-fuzzer`.

## File boundaries

`flow` owns execution semantics; `script` adapts JS to flow callbacks; `internal/cli` owns projects, flags, output, and command orchestration; `cmd/reqfuzzy` only exits with the handler's result. Existing raw request and transport packages remain the transport boundary. Imported files and hook source are read as local project data, never fetched implicitly.

All tests use temporary files and local HTTP servers. No external target is needed. Preserve the original checkout's uncommitted `main.go` edit. Keep Go 1.24 as the module floor.

Delivery: draft PR #12 contains the CLI and script slice; PRs #10 and #11 are merged into the development branch. Local race/vet/build checks, Go 1.24.4 tests, and the actual CLI demo passed.
