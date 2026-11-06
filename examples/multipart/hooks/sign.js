function beforeSend(ctx) {
  ctx.request.setHeader("X-Signature", crypto.hmacSha256Bytes(encoding.base64Encode(ctx.vars.get("signing_key")), ctx.request.bodyBase64));
}
