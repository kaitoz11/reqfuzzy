# Import a HAR and review a suggested flow

The `capture` package turns a HAR 1.2 file into named raw requests and a draft flow. It uses the captured **responses** to suggest where a value from one step is reused by a later request. Import and inference are offline and never contact the captured host. Use the CLI to import and review a project, or register the generated request files with `flow.Runner` in Go.

The parser follows the [HAR format specification](https://webperfwg.org/specs/HAR/Overview.html), including its UTF-8 requirement. Export a HAR with response content; captures with missing or sanitized response bodies may produce few or no links. Keep the source HAR in a private location because it can include tokens, cookies, and sensitive response data.

## Generate the draft

Place the capture at `.reqfuzzy/session.har`. The program below reads it, writes private raw-request files under the same Git-ignored directory, and saves `suggested-flow.yaml` for review. It prints link paths and confidence, never captured values.

```go
package main

import (
    "fmt"
    "log"
    "os"
    "path/filepath"

    "github.com/kaitoz11/reqfuzzy/pkg/attacker/capture"
)

func main() {
    data, err := os.ReadFile(filepath.Join(".reqfuzzy", "session.har"))
    if err != nil { log.Fatal(err) }

    imported, err := capture.ParseHAR(data)
    if err != nil { log.Fatal(err) }

    root := filepath.Join(".reqfuzzy", "captures", "session")
    paths, err := imported.WriteRequests(filepath.Join(root, "requests"))
    if err != nil { log.Fatal(err) }

    suggestion, err := capture.SuggestFlow(imported)
    if err != nil { log.Fatal(err) }
    yamlData, err := suggestion.YAML()
    if err != nil { log.Fatal(err) }
    if err := os.WriteFile(filepath.Join(root, "suggested-flow.yaml"), yamlData, 0600); err != nil {
        log.Fatal(err)
    }

    fmt.Printf("wrote %d requests and %d suggested links\n", len(paths), len(suggestion.Links))
    for _, link := range suggestion.Links {
        fmt.Printf("%s.%s -> %s %s:%s (%s)\n",
            link.FromStep, link.FromJSONPath, link.ToStep,
            link.ToLocation, link.ToPath, link.Confidence)
    }
}
```

Read and edit the YAML before replay. A suggested link is only a matching value observed in the capture; it does not prove the application requires that dependency. Register the returned `paths` with `attacker.RequestStore`, load the reviewed YAML with `flow.LoadYAML`, and use the [flow runner](flow-mutation.md) to execute it against a target you control.

## Current inference boundaries

- Sources are scalar JSON response values and unique named response `Set-Cookie` values. Strings need at least six characters; numbers need at least four digits. Repeated or ambiguous prior values and responses with duplicate JSON object keys are left unresolved. Cookie destinations prefer a unique same-name `Set-Cookie` source when available; other matching scalar sources follow the usual ambiguity rules. Response headers are retained during HAR parsing and invalid header syntax is rejected.
- Destinations are exact path segments, query values, exact headers, `Authorization: Bearer <token>` (case insensitive scheme), scalar JSON body values, UTF-8 URL-encoded form fields, and named request cookies. Path matching decodes each escaped segment once; an encoded slash remains within its segment. Path bindings use a quoted zero-based slot index (`path: "2"` for `/api/items/{id}`), counting empty slots between slashes. Repeated query/form keys, cookie names, and header names are left unresolved. Cookie values keep literal percent text. Malformed/unsupported form encoding or malformed Cookie syntax contributes no links for that location. The runner supports generated bindings. Multipart bodies remain outside this inference slice.
- A response with no captured body or invalid JSON contributes no source values. Base64 encoded response content is decoded. Params-only URL-encoded request bodies are reconstructed; params-only multipart requests are rejected because their bytes are unavailable.
- The YAML contains executable steps and bindings. Confidence and source/destination provenance remain in `Suggestion.Links` so the strict flow loader accepts the file.

`WriteRequests` is idempotent for identical bytes and refuses to overwrite an edited request. Imported files use mode `0600`; their parent directory is created with mode `0700`. `.reqfuzzy/` is ignored by Git.
