function beforeSend(ctx) {
  const body = JSON.parse(ctx.request.body);
  body.email = "reqfuzzy-" + Date.now().toString(36) + "-" +
    Math.random().toString(36).slice(2) + "@example.invalid";
  ctx.request.body = JSON.stringify(body);
}
