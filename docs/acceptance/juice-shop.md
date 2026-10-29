# Independent application acceptance

On 2026-10-30, reqfuzzy's existing journey engine was exercised against local OWASP Juice Shop v20.3.0, selected after the user delegated acceptance-target choice. Docker was bound to loopback only. The immutable image manifest was `bkimminich/juice-shop@sha256:cea5a4af4aacee498c491491af0408934ec81d004035c0a02ef3e54395e3bf27`.

`TestJuiceShopCapturedCheckoutAndReplay` recorded six actual HTTP exchanges into a HAR, imported that capture, retained the generated suggestion, and confirmed four inferred authorization links. It then applied the reviewed dependencies and path hooks from [the example project](../../examples/juice-shop/README.md), keeping the actual captured request bytes.

| Trial | Outcome | Sent quantity | Persisted total |
|---|---|---:|---:|
| Baseline | pass | 2 | 3.98 |
| Negative | fail | -10 | -19.90 |
| Zero | pass | 0 | 0 |
| Replay negative | fail | -10 | -19.90 |

Campaign and replay returned exit code 3. The negative case's mutation proof was `verified`. Checks required exactly one persisted order, its ID to match the checkout response, and its total to be nonnegative. The test checked distinct account IDs across the baseline, cases, and reconstructed replay, along with absence of the fixture password and captured token from normal evidence.

The passing execution retained private artifacts under `.reqfuzzy/juice-shop-verified/`. Its HAR and imported project contain disposable application credentials and remain ignored by Git. The executable test and example provide reproducibility without publishing that capture.

The built `cmd/reqfuzzy` binary also ran `flow test` directly against `examples/juice-shop`, independently of the test helper. It returned exit 3 with baseline pass, negative fail, zero pass, and a verified mutation. Those private artifacts are under `.reqfuzzy/juice-shop-example/`.

This validates a real third-party API's minimal checkout route; it does not claim full browser-workflow coverage or general application compatibility. No custom application-side endpoint or response shim was added. The initial acceptance used explicit path scripts. The subsequent path-dependency feature replaces them with visible declarative bindings; conservative inference still skips Juice Shop's short numeric IDs. Broader request mutation locations and a visual dependency view remain product work.

After replacing URL hooks with path bindings, the same capture/campaign/reconstruction acceptance passed again. Its private artifacts are under `.reqfuzzy/juice-shop-path-bindings/`; sent quantities and persisted totals matched the table above, with fresh accounts across all five baseline/case/replay trials.
