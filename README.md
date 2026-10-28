# reqfuzzy

I'm bored... So I build my very own framework to fuzz complex, stateful API workflows.

The first stateful-flow slice can replay named raw requests, carry response values to later steps, mutate one step, and compare the unchanged and changed journeys. See [Flow mutation](docs/flow-mutation.md) for the YAML format and Go API.

Captured HAR 1.2 traffic can now produce named raw requests and a reviewable suggested flow. See [HAR flow inference](docs/har-flow-inference.md).
