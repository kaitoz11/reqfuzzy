function afterResponse(ctx) {
  const body = JSON.parse(ctx.response.body);
  ctx.vars.set("token", body.access_token);
  ctx.vars.set("signing_key", body.signing_key);
}
