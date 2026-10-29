function beforeSend(ctx) {
  ctx.request.url = "/rest/basket/" + encodeURIComponent(ctx.vars.getRaw("basket_id")) + "/checkout";
}
