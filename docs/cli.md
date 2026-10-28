# Reqfuzzy command line

Build `go build -o bin/reqfuzzy ./cmd/reqfuzzy`. Flags precede positional arguments. The existing Go packages remain available when a target needs custom Go callbacks.

## Import and inspect

```sh
bin/reqfuzzy import --out .reqfuzzy/demo .reqfuzzy/session.har
bin/reqfuzzy flow show --project .reqfuzzy/demo
bin/reqfuzzy flow show --project .reqfuzzy/demo --json
```

Import parses and suggests bindings offline. It creates a new directory containing `project.yaml`, editable `flow.yaml`, `links.json`, private raw request files, and a `hooks/` directory. Existing output directories are refused, preserving operator edits. Parsing and inference complete before the new directory is reserved; if writing fails, partial output remains for inspection. Captured traffic under `.reqfuzzy/` is ignored by Git.

A HAR with multiple origins needs selection, for example `import --origin https://api.example.test --out .reqfuzzy/demo capture.har`. Review the suggested sequence and remove irrelevant captured steps before replay. `flow show` derives its edges from the current YAML, including script-provided variables, so edits are reflected immediately.

## Run and compare

```sh
bin/reqfuzzy flow run --project .reqfuzzy/demo --base-url https://api.example.test
bin/reqfuzzy flow compare --project .reqfuzzy/demo --base-url https://api.example.test --step transfer --location json --path amount --value 99 --json
```

Replay requires an explicit HTTP(S) base URL. Every captured target must be a relative path beginning with `/`; absolute, authority-relative, and malformed targets are rejected before any replay request. The CLI aligns Host with the selected target before a signing hook runs. Captured cookies are removed and each actor's fresh client jar carries cookies between steps. Different actor names use independent clients.

`compare` accepts one set-value mutation. Locations are `json`, `header`, and `query`. For JSON, `--value` is a raw scalar such as `99`, `true`, or `'"text"'`; it preserves large numeric IDs. Header and query values are plain text. Header replacement is case insensitive; query replacement replaces the whole key, including repeated occurrences. The baseline and changed runs each replay the full journey with fresh clients.

Use `--timeout 30s` for the command execution deadline and `--script-timeout 1s` for each JavaScript invocation. Those are the defaults. Ctrl-C cancels replay. Hooks are loaded from `PROJECT/hooks`; `--hooks DIR` explicitly chooses another script directory. Default hook symlinks must stay within the project, and hook names cannot contain path separators.

## Results

Human output lists step statuses and response SHA-256 hashes. `--json` emits exactly one document with `format_version: 1`, `command`, `result`, and an optional structured `error`. Run results include `flow_name`, `steps`, and `failed_step_id` when relevant. Comparison results contain `baseline` and `mutated` run summaries. Bodies, headers, and variable values are omitted from normal command output; the Go API exposes complete in-memory traces when needed. A script's own thrown error text is included as its diagnostic, so keep secrets out of thrown messages.

| Exit code | Meaning |
|---|---|
| 0 | Import, inspection, or execution succeeded; differing responses are still successful execution. |
| 1 | Arguments, project files, import data, or script preflight are invalid. |
| 2 | Execution failed, timed out, or was canceled; completed step summaries are retained. |

See [script hooks](script-hooks.md) for dynamic request transformations and response logic, and the runnable project in `examples/scripted-flow`.
