function afterResponse(ctx) {
  if (ctx.response.status === 401) ctx.flow.next("refresh");
}
