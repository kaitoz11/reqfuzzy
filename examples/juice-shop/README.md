# Juice Shop checkout journey

This project exercises a local OWASP Juice Shop **v20.3.0** instance. It creates a fresh account for every baseline, case, and replay; logs in; binds the new token and basket ID; adds product 1; updates its quantity; checks out; and reads the persisted order history.

The invariant is that an order total cannot be negative. On this deliberately vulnerable application, quantity `-10` produces a total of `-19.90`, so the expected campaign exit code is **3** (a valid invariant failure). Quantity `0` passes this particular invariant. The baseline quantity `2` produces `3.98`. This checks the API's minimal checkout contract; it does not exercise the browser's address, card, or delivery selection screens.

From the repository root, start the pinned local fixture:

```sh
docker run --rm -d --name reqfuzzy-juice-shop \
  -p 127.0.0.1:3000:3000 \
  bkimminich/juice-shop@sha256:cea5a4af4aacee498c491491af0408934ec81d004035c0a02ef3e54395e3bf27
```

After `http://127.0.0.1:3000/rest/admin/application-version` returns version `20.3.0`:

```sh
go build -o .reqfuzzy/bin/reqfuzzy ./cmd/reqfuzzy
.reqfuzzy/bin/reqfuzzy flow show --project examples/juice-shop
.reqfuzzy/bin/reqfuzzy flow test --project examples/juice-shop \
  --base-url http://127.0.0.1:3000 --out .reqfuzzy/juice-shop-run --json
.reqfuzzy/bin/reqfuzzy flow replay --project examples/juice-shop \
  --base-url http://127.0.0.1:3000 --run .reqfuzzy/juice-shop-run \
  --case negative --out .reqfuzzy/juice-shop-replay --json
docker stop reqfuzzy-juice-shop
```

Both output directories must be new. The fake password in these files is solely for accounts created in this disposable fixture. Normal evidence redacts passwords, tokens, and the configured email fields. Remove the container when finished to discard its application state.

To start from an actual HTTP capture rather than these sample request files, run the opt-in acceptance test:

```sh
REQFUZZY_JUICE_SHOP_URL=http://127.0.0.1:3000 \
  go test ./internal/cli -run '^TestJuiceShopCapturedCheckoutAndReplay$' -count=1 -v
```

Set `REQFUZZY_ACCEPTANCE_OUT` to a new absolute directory to retain the private HAR, imported project, campaign, and replay. The test only accepts a literal `http://127.0.0.1:PORT` target and refuses redirects during capture. It is skipped by normal test runs and never starts Docker itself.

HAR import infers the four Bearer-token links in this capture. Short numeric IDs are outside conservative inference, so the reviewed flow explicitly binds item/basket IDs with `location: path, path: "2"`. These dependencies appear in `flow show`, and the quantity mutation remains independent of path binding. Longer unique IDs can also be inferred from a capture. The fresh-account hook remains responsible for generating a new email.

The application behavior is defined in the pinned upstream [basket-item routes](https://github.com/juice-shop/juice-shop/blob/v20.3.0/routes/basketItems.ts), [checkout route](https://github.com/juice-shop/juice-shop/blob/v20.3.0/routes/order.ts), and [order-history route](https://github.com/juice-shop/juice-shop/blob/v20.3.0/routes/orderHistory.ts).
