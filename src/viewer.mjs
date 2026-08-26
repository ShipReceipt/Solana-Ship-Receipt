import { createServer } from "node:http";
import { renderHtml, verifyEnvelope } from "./receipt.mjs";

function securityHeaders(contentType) {
  return {
    "content-type": contentType,
    "cache-control": "no-store",
    "content-security-policy":
      "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    "referrer-policy": "no-referrer",
    "cross-origin-resource-policy": "same-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
  };
}

function send(response, status, headers, body) {
  response.writeHead(status, headers);
  response.end(body);
}

export async function startViewer({
  envelope,
  port = 8787,
  host = "127.0.0.1",
  network = false,
} = {}) {
  if (host !== "127.0.0.1")
    throw new Error("The local viewer only binds to 127.0.0.1");
  if (!envelope) throw new Error("An envelope is required");
  const result = await verifyEnvelope(envelope, { network });
  const schemaCheck = result.checks.find((check) => check.name === "schema");
  if (schemaCheck?.status === "failed")
    throw new Error(`Cannot serve invalid receipt: ${schemaCheck.message}`);
  const html = renderHtml(envelope, result);
  const server = createServer((request, response) => {
    if (!["GET", "HEAD"].includes(request.method)) {
      send(
        response,
        405,
        { ...securityHeaders("text/plain; charset=utf-8"), allow: "GET, HEAD" },
        "Method Not Allowed",
      );
      return;
    }
    const path = new URL(request.url || "/", `http://${host}`).pathname;
    if (path === "/") {
      send(
        response,
        200,
        securityHeaders("text/html; charset=utf-8"),
        request.method === "HEAD" ? "" : html,
      );
      return;
    }
    if (path === "/api/receipt") {
      const body = `${JSON.stringify(envelope, null, 2)}\n`;
      send(
        response,
        200,
        securityHeaders("application/json; charset=utf-8"),
        request.method === "HEAD" ? "" : body,
      );
      return;
    }
    if (path === "/api/verification") {
      const body = `${JSON.stringify(result, null, 2)}\n`;
      send(
        response,
        200,
        securityHeaders("application/json; charset=utf-8"),
        request.method === "HEAD" ? "" : body,
      );
      return;
    }
    send(
      response,
      404,
      securityHeaders("text/plain; charset=utf-8"),
      request.method === "HEAD" ? "" : "Not Found",
    );
  });

  await new Promise((resolve, reject) => {
    const onError = (error) => {
      server.off("listening", resolve);
      reject(error);
    };
    server.once("error", onError);
    server.listen(port, host, () => {
      server.off("error", onError);
      resolve();
    });
  });
  const address = server.address();
  const actualPort =
    typeof address === "object" && address ? address.port : port;
  return {
    server,
    port: actualPort,
    url: `http://${host}:${actualPort}/`,
    close: () =>
      new Promise((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      ),
  };
}
