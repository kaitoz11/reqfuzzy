# Visual flow map and editor

Generate a private, self-contained HTML editor from a project:

```sh
bin/reqfuzzy flow map --project .reqfuzzy/demo --out .reqfuzzy/demo-map.html
```

For a campaign, include its verification flow and reference checks:

```sh
bin/reqfuzzy flow map --project examples/juice-shop --test tests.yaml --out .reqfuzzy/checkout-map.html --json
```

Open the resulting file in a browser. Generation and editing send no target requests and execute no hooks. A new output path is required; the CLI refuses overwrite. Files use mode 0600 and new parent directories use 0700. The editor needs no server, account, external fonts, or network connection.

The artifact contains flow configuration, including binding prefixes, registered request names, and optional campaign references. It excludes captured request contents, response data, extracted values, target URLs, hook source, and case/check operands.

## Inspect and author a journey

The graph places requests in execution order within actor lanes. Gray arrows show request order; colored, labeled arrows show variable dependencies and their locations. The map describes the authored flow, not the outcome of a particular run. Click a node to edit its request, actor, status, hooks, response extractions, provided variables, and bindings. Click an edge to focus its binding.

All six locations are available: JSON, header, query, path, form, and named cookie. Extractions support JSON selectors and response `Set-Cookie` names. Provided variables require an after-response hook. Add, delete, or reorder steps using registered request templates; request files and script source remain in the project.

Search highlights matching steps/variables. The location filter emphasizes one class of dependencies. Use zoom or Fit to navigate larger graphs; narrow screens place the inspector below the canvas. Nodes and edges support keyboard selection, and Up/Down arrows move between graph nodes.

Changes update the graph immediately. Undo/redo and Reset operate in memory. Empty selectors, invalid statuses, duplicate IDs/variables, forward references, unknown requests, and broken campaign references disable export. The CLI still checks hook files and request structure during execution preflight.

With `--test`, Journey and Verification select which definition to edit/export while the graph shows both. Cross-phase edges point to their real source, even when phases use equal step IDs. The campaign target is highlighted. Campaign definitions are read-only in this editor; target/check step names and referenced variables must remain valid. Edit the campaign file separately to change its assertions or mutation cases.

## Save the edited definitions

Export downloads the active flow as `flow.yaml` or the verification filename. Apply each downloaded file to the corresponding project file before running. The browser cannot write project files or execute requests.

Exports use JSON syntax accepted by the strict YAML loader. This preserves selectors, prefixes, cookie names, and integer statuses without introducing a browser YAML dependency. Unicode line-break characters and markup are escaped without changing their values. Existing evidence fingerprints detect edited project definitions; use a new test run after applying changes.

## Developer browser check

The Go tests execute the pure graph/editor core with Goja and round-trip exports through the real loaders. Stable CI also runs actual browser authoring, validation, download, hostile-label, and narrow-layout checks. The browser check is optional locally:

```sh
go build -o .reqfuzzy/bin/reqfuzzy ./cmd/reqfuzzy
npm --prefix .reqfuzzy/browser install --no-audit --no-fund playwright@1.64.1
node .reqfuzzy/browser/node_modules/playwright/cli.js install chromium
node scripts/flow-map-browser.mjs
```

Set `REQFUZZY_BROWSER` to use an existing compatible Chromium binary or `REQFUZZY_BIN` to use another reqfuzzy build. The script retains maps, exported definitions, and desktop/narrow screenshots in a new ignored `.reqfuzzy/flow-map-browser-*` directory. Node and Playwright are development tools; reqfuzzy has no Node runtime dependency.
