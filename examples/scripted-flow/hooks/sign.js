function beforeSend(ctx) {
  // The selected mutation has already been applied to this body.
  ctx.request.setHeader(
    "X-Signature",
    crypto.hmacSha256("local-demo-key", ctx.request.body)
  );
}
