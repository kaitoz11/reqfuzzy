# Multipart delivery acceptance

The `examples/multipart` project exercises all four multipart dependency locations, an arbitrary binary file (`00 ff 01 66 69 6c 65`), JavaScript HMAC over final bytes, a binary response acknowledgment, generated traversal filenames, and downstream server state. The independent fixture uses Go's standard multipart reader and in-memory metadata; no uploaded file is written to disk.

`TestActualMultipartCaptureBinarySigningCampaignAndReplay` captures real HTTP requests/responses, imports HAR, checks inferred text/full-filename/media-type bindings, then authors binary file binding and signing. Both secure and vulnerable modes create fresh state for every trial. Secure rejection yields pass; vulnerable acceptance yields fail with verified sent-filename proof. A selected reconstruction reproduces that classification; budget/source drift stop before traffic. Normal multipart request bodies are omitted with hashes. Parser and real HTTP proof tests cover file bytes, metadata, explicit ordinals, removal shifts, boundary collisions, restored mutations, and unsupported encoding.

The built CLI ran the vulnerable campaign at `.reqfuzzy/upload-delivery-20261106/` and selected reconstruction at `.reqfuzzy/upload-replay-20261106/`: both returned exit 3, both generated cases were accepted with 201 and failed `stored-path-safe`, and every mutation proof was `verified`. Planned request bounds were nine and six. The local fixture was stopped afterward.

Browser acceptance `.reqfuzzy/flow-map-browser-MKhgGT/` edited an upload file binding to `index:1`, blocked noncanonical ordinals and file prefixes, exported/reloaded the flow, and sent zero network requests. Existing reference/checkout/recovery/payload authoring checks also passed.

Review found that named fields incorrectly recognized `attachment` dispositions. Red regressions reproduced verified proof after a hook changed form-data to attachment; named selectors now require form-data, while explicit ordinal selectors can address other raw parts. Parser, sent-proof, and capture tests cover this boundary. CI and final review remain required before development integration.
