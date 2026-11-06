function afterResponse(ctx) {
  if (ctx.response.status === 201 && (ctx.response.body !== null || ctx.response.bodyBase64 !== "AP8B")) throw new Error("invalid binary acknowledgment");
}
