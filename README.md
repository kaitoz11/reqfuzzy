# Historical PayInt rework notes

Implementation continues in [kaitoz11/reqfuzzy](https://github.com/kaitoz11/reqfuzzy), using its existing Go code. The separate Python `kvar` engine described in these September design notes is superseded.

Reqfuzzy owns captured requests, executable API flows, dynamic request transformations, inference, and testing. `payintv3` remains the behavior and payload reference. Current designs and implementation plans live in reqfuzzy's `docs/superpowers/` directory. These notes remain available as historical requirements research.

See [current delivery status](CURRENT_STATUS.md) for implemented capabilities and the next product work.
