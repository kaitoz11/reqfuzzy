# JavaScript hooks

Reqfuzzy embeds [Goja](https://github.com/dop251/goja) for synchronous JavaScript. The dependency is pinned to a revision compatible with Go 1.24. This is reqfuzzy's hook API; Node.js, npm modules, filesystem access, network calls, timers, and `process` are not provided. Existing Go callbacks remain available through `flow.Runner`.

Put a named script in `hooks/<name>.js` and reference that name from a step. This flow logs in with a response script, then signs a request:

```yaml
name: scripted-example
steps:
  - id: login
    request: login
    after_response: session
    provides: [token]
  - id: create
    request: create
    bind:
      - location: header
        path: Authorization
        variable: token
        prefix: "Bearer "
    before_send: sign
```

`hooks/session.js`:

```javascript
function afterResponse(ctx) {
  const body = JSON.parse(ctx.response.body);
  ctx.vars.set("token", body.token);
}
```

`hooks/sign.js`:

```javascript
function beforeSend(ctx) {
  ctx.request.setHeader(
    "X-Signature",
    crypto.hmacSha256("target-specific-key", ctx.request.body)
  );
}
```

Bindings and the selected mutation run before `beforeSend`, so the signature covers the final body. The CLI also prepares the target Host before that hook. After a response arrives, the runner checks its expected status, extracts YAML variables, calls `afterResponse`, and verifies every declared `provides` variable. A later binding can refer to those declared names. Duplicate declarations or missing provided values stop the flow.

## Context

| API | Behavior |
|---|---|
| `ctx.request.method`, `.url`, `.body` | Mutable strings in `beforeSend`. URL is a relative path including the effective query. Body is UTF-8 text. |
| `ctx.request.getHeader(name)` | Read the first value, ignoring header-name case. |
| `ctx.request.setHeader(name, value)` | Replace all case variants with one validated value. |
| `ctx.request.removeHeader(name)` | Remove all case variants. |
| `ctx.response.status`, `.body`, `.getHeader(name)` | Read response data in `afterResponse`. |
| `ctx.vars.get(name)` | Read a scalar; throws when missing or outside the supported safe JS number range. |
| `ctx.vars.set(name, value)` | Store a string, finite safe number, or boolean. |
| `ctx.vars.getRaw(name)` | Read the exact JSON scalar text. |
| `ctx.vars.setRaw(name, jsonText)` | Store a validated raw JSON scalar without numeric conversion. |
| `crypto.sha256(text)` | UTF-8 SHA-256, hexadecimal output. |
| `crypto.hmacSha256(key, text)` | UTF-8 HMAC-SHA-256, hexadecimal output. |
| `encoding.base64Encode(text)` / `.base64Decode(text)` | Encode UTF-8 text or decode to valid UTF-8 text. |

Each invocation receives a fresh JavaScript VM. Store cross-step state explicitly through `ctx.vars`; JavaScript globals are not shared. Request and variable edits are staged until the hook succeeds. Exceptions, invalid edits, Promise returns, or deadlines discard the staged changes and stop the affected run. All named callback exports are checked before target requests.

Hooks return no value and cannot be asynchronous. The default deadline is one second per invocation; the CLI's overall timeout also bounds preflight execution. Request and response bodies entering JavaScript must be UTF-8. Use the Go API for binary transformations and additional crypto libraries.

## Numeric IDs

JavaScript numbers cannot exactly represent every JSON integer. Keep large IDs in YAML extraction/binding or use raw operations:

```javascript
function beforeSend(ctx) {
  ctx.request.body = '{"transactionId":' + ctx.vars.getRaw("transaction_id") + '}';
}
```

`ctx.vars.get("transaction_id")` fails for unsafe magnitudes instead of silently rounding them. `JSON.parse()` in your own script follows JavaScript's number semantics; use raw operations when exact digits matter.
