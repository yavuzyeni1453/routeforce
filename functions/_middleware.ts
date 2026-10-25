export const onRequest: PagesFunction = async (context) => {
  const host = new URL(context.request.url).hostname.toLowerCase();
  if (host === "lg.routeforce.cloud" && new URL(context.request.url).pathname === "/") {
    return Response.redirect(new URL("/lg.html", context.request.url), 302);
  }
  return context.next();
};