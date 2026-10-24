# Flow mutation

`pkg/attacker/flow` runs a small, explicit API journey from raw requests registered in `attacker.RequestStore`. It extracts scalar JSON response values, binds them into later requests, and lets Go callbacks change or sign a request before send. `Compare` runs the journey unchanged and then with one mutation; each run gets fresh clients per actor.

## Prepare raw requests

Save these requests as `requests/login.txt`, `requests/create.txt`, and `requests/read.txt`. Replace the paths, headers, and bodies with captured requests for your local API.

```http
GET /login HTTP/1.1
Host: 127.0.0.1:8080

```

```http
POST /create HTTP/1.1
Host: 127.0.0.1:8080
Content-Type: application/json

{"amount":10}
```

```http
GET /read HTTP/1.1
Host: 127.0.0.1:8080

```

The server for this example returns `{"token":"..."}` from `/login`, `{"id":123}` from `/create`, and accepts `GET /read?id=123`. It should use a session cookie or another per-run identity so the two comparison runs can create independent state.

## Define the flow

Save this as `flow.yaml`:

```yaml
name: item-journey
steps:
  - id: login
    request: login
    expect_status: 200
    extract:
      - name: token
        json: token
  - id: create
    request: create
    bind:
      - location: header
        path: Authorization
        variable: token
    before_send: sign
    expect_status: 201
    extract:
      - name: item_id
        json: id
  - id: read
    request: read
    bind:
      - location: query
        path: id
        variable: item_id
    expect_status: 200
```

`json` uses `gjson` paths for extraction and `sjson` paths for binding. A JSON binding preserves the captured value's type and numeric precision. `header` and `query` bindings use its text form. A missing variable, missing scalar, unknown request, or unmet status stops the run and returns the completed trace.

## Run a comparison

The Go program below assumes a local API at `http://127.0.0.1:8080`. The `sign` hook runs after the mutation, so it hashes the exact body being sent.

```go
package main

import (
    "context"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "os"

    "github.com/kaitoz11/reqfuzzy/pkg/attacker"
    "github.com/kaitoz11/reqfuzzy/pkg/attacker/flow"
)

func main() {
    data, err := os.ReadFile("flow.yaml")
    if err != nil { panic(err) }
    definition, err := flow.LoadYAML(data)
    if err != nil { panic(err) }

    store := attacker.NewRequestStore()
    store.RegisterRequestFilePath("login", "requests/login.txt")
    store.RegisterRequestFilePath("create", "requests/create.txt")
    store.RegisterRequestFilePath("read", "requests/read.txt")

    runner := flow.Runner{
        Store: store,
        NewClient: func(actor string) (*attacker.HClient, error) {
            client := attacker.NewHClient()
            client.UseBaseURL("http://127.0.0.1:8080")
            return client, nil
        },
        BeforeSend: map[string]flow.BeforeSend{
            "sign": func(request attacker.Request, variables flow.Variables) error {
                digest := sha256.Sum256(request.Body)
                request.SetHeader("X-Body-Signature", hex.EncodeToString(digest[:]))
                return nil
            },
        },
    }
    mutation := flow.StepMutation{
        StepID: "create",
        Apply: func(request attacker.Request, variables flow.Variables) error {
            return request.UpdateJsonBody("amount", 99)
        },
    }
    comparison, err := runner.Compare(context.Background(), definition, mutation)
    if err != nil { panic(err) }
    fmt.Printf("baseline final response: %s\n", comparison.Baseline.Steps[2].ResponseBody)
    fmt.Printf("changed final response: %s\n", comparison.Mutated.Steps[2].ResponseBody)
}
```

`Runner.Run` is available when only one execution is needed. Its optional `StepMutation` targets exactly one step. `Runner.Compare` always replays prerequisite steps in both runs. A client factory can select different accounts with `actor`, while reusing each account's client within one run.

Results contain prepared request headers and bodies in memory. Treat them as sensitive when printing or persisting them. Raw request files alone can be used to author a flow; automatic flow inference will need captured responses as well.
