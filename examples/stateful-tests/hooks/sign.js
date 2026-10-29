function beforeSend(ctx) {
  ctx.request.setHeader(
    "X-Signature",
    crypto.hmacSha256(ctx.vars.get("signing_key"), ctx.request.body)
  );
}
