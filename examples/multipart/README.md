# Signed multipart upload

The local in-memory API issues fresh tokens, one-use nonces, signing keys, and base64 file data. Reqfuzzy binds all four multipart locations, signs the final binary body, handles a binary acknowledgment, mutates filenames, and reads stored state after either acceptance or rejection. The server uses Go's standard multipart parser and never writes uploaded files to disk.

```sh
go build -o .reqfuzzy/bin/reqfuzzy ./cmd/reqfuzzy
go run ./examples/multipart/mock --vulnerable
```

In another terminal:

```sh
.reqfuzzy/bin/reqfuzzy flow plan --project examples/multipart --json
.reqfuzzy/bin/reqfuzzy flow test --project examples/multipart --base-url http://127.0.0.1:8099 --out .reqfuzzy/upload-run --json
.reqfuzzy/bin/reqfuzzy flow replay --project examples/multipart --base-url http://127.0.0.1:8099 --run .reqfuzzy/upload-run --case traversal-000001 --out .reqfuzzy/upload-replay --json
.reqfuzzy/bin/reqfuzzy flow map --project examples/multipart --test tests.yaml --out .reqfuzzy/upload-map.html
```

Vulnerable mode accepts `../outside.bin` and `../../another.bin`, so the downstream `unsafe == false` invariant fails (exit 3) with verified mutation proof. Start without `--vulnerable` to reject those names with 422 and pass the invariant. Each baseline/case/replay creates a fresh session and re-signs exact bytes. A campaign bounds nine requests; a selected reconstruction bounds six.

Normal evidence omits/hash-protects opaque multipart bodies and redacts credentials. `--include-sensitive` retains exact private base64 traces. No output directories are overwritten. The CLI integration test independently records actual UTF-8 multipart traffic, imports it, checks inferred text/filename/media-type dependencies, authors the binary source binding, and proves signing, campaign classification, reconstruction, budget refusal, and source-drift refusal.

See [request locations](../../docs/request-locations.md#multipart-bodies) for selectors, duplicate names, encodings, byte preservation, and limits.
