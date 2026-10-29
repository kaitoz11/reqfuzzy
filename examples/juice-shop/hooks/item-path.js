function beforeSend(ctx) {
  ctx.request.url = "/api/BasketItems/" + encodeURIComponent(ctx.vars.getRaw("item_id"));
}
