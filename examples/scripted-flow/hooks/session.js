function afterResponse(ctx) {
  const body = JSON.parse(ctx.response.body);
  ctx.vars.set("token", body.token);
}
