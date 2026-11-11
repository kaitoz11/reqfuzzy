# Historical PayInt rework notes

Implementation is delivered in [kaitoz11/reqfuzzy](https://github.com/kaitoz11/reqfuzzy), using its existing Go code. The separate Python `kvar` engine described in these September design notes is superseded.

Reqfuzzy owns captured requests, executable API flows, dynamic request transformations, inference, and testing. `payintv3` remains the behavior and payload reference. Current designs and implementation plans live in reqfuzzy's `docs/superpowers/` directory. These notes remain available as historical requirements research.

See [current delivery status](CURRENT_STATUS.md) for implemented capabilities and the next product work.

The complete history of this planning repository is preserved on reqfuzzy's [`archive/payint-kvar`](https://github.com/kaitoz11/reqfuzzy/tree/archive/payint-kvar) branch. A browsable snapshot lives under [`docs/archive/payint-kvar`](https://github.com/kaitoz11/reqfuzzy/tree/feat/req-fuzzer/docs/archive/payint-kvar) on the development branch. The September proposals remain historical and unratified where marked; current runtime contracts are documented in reqfuzzy.
