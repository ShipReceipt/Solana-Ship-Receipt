import { createServer } from "node:http";
import {
  createEnvelope,
  createPayload,
  renderHtml,
  verifyEnvelope,
} from "./receipt.mjs";

function securityHeaders(contentType) {
  return {
    "content-type": contentType,
    "cache-control": "no-store",
    "content-security-policy":
      "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    "referrer-policy": "no-referrer",
    "cross-origin-resource-policy": "same-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
  };
}

function parseRequestBody(rawBody, contentType) {
  if (!rawBody) return {};
  const type = contentType || "";
  if (type.includes("application/json")) return JSON.parse(rawBody);
  if (type.includes("application/x-www-form-urlencoded"))
    return Object.fromEntries(new URLSearchParams(rawBody));
  if (type.includes("multipart/form-data")) {
    const boundary = type.match(/boundary=(?:"([^"]+)"|([^;]+))/i)?.[1] || type.match(/boundary=(?:"([^"]+)"|([^;]+))/i)?.[2];
    if (!boundary) return {};
    const payload = {};
    const parts = rawBody.split(`--${boundary}`);
    for (const part of parts) {
      const text = part.trim();
      if (!text || text === "--") continue;
      const headerIndex = text.indexOf("\r\n\r\n");
      if (headerIndex === -1) continue;
      const headersText = text.slice(0, headerIndex);
      const bodyText = text.slice(headerIndex + 4).replace(/\r\n$/, "");
      const nameMatch = headersText.match(/name="([^"]+)"/i);
      if (!nameMatch) continue;
      const key = nameMatch[1];
      payload[key] = bodyText;
    }
    return payload;
  }
  return {};
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
  allowPublicHost = false,
} = {}) {
  if (host !== "127.0.0.1" && !allowPublicHost)
    throw new Error(
      "The local viewer only binds to 127.0.0.1 unless explicitly enabled",
    );
  if (!envelope) throw new Error("An envelope is required");
  const result = await verifyEnvelope(envelope, { network });
  const schemaCheck = result.checks.find((check) => check.name === "schema");
  if (schemaCheck?.status === "failed")
    throw new Error(`Cannot serve invalid receipt: ${schemaCheck.message}`);
  const html = renderHtml(envelope, result);
  const uploadPage = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Local viewer</title>
  <style>
    body { font-family: sans-serif; margin: 2rem; color: #10231d; background: #f2f5f4; }
    main { max-width: 760px; margin: 0 auto; background: #fff; border: 1px solid #d7e0dc; border-radius: 12px; padding: 2rem; }
    textarea { width: 100%; min-height: 220px; margin-top: 0.75rem; }
    button { margin-top: 0.75rem; padding: 0.7rem 1rem; }
    .note { color: #5d6d67; }
  </style>
</head>
<body>
  <main>
    <h1>Local viewer</h1>
    <p class="note">Paste a canonical receipt JSON to review it in the same local viewer flow.</p>
    <form method="post" action="/" accept-charset="utf-8" enctype="multipart/form-data">
      <label for="receipt">Receipt JSON</label>
      <textarea id="receipt" name="receipt" placeholder="{\n  \"version\": 1,\n  \"payload\": { ... },\n  \"receiptHash\": \"...\"\n}"></textarea>
      <p><label for="receipt-file">Or upload a JSON file</label><br><input id="receipt-file" type="file" name="receipt-file" accept="application/json"></p>
      <button type="submit">Review receipt</button>
    </form>
  </main>
</body>
</html>`;

  const reviewPage = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Verify receipt</title>
  <style>
    body { font-family: sans-serif; margin: 2rem; color: #10231d; background: #f2f5f4; }
    main { max-width: 760px; margin: 0 auto; background: #fff; border: 1px solid #d7e0dc; border-radius: 12px; padding: 2rem; }
    textarea { width: 100%; min-height: 220px; margin-top: 0.75rem; }
    button { margin-top: 0.75rem; padding: 0.7rem 1rem; }
    .note { color: #5d6d67; }
    .error { color: #b42318; font-weight: 600; }
  </style>
</head>
<body>
  <main>
    <h1>Verify receipt</h1>
    <p class="note">Paste a canonical receipt JSON and submit it to the verifier API.</p>
    <form method="post" action="/api/verify" accept-charset="utf-8">
      <label for="receipt">Receipt JSON</label>
      <textarea id="receipt" name="receipt" placeholder="{\n  \"version\": 1,\n  \"payload\": { ... },\n  \"receiptHash\": \"...\"\n}"></textarea>
      <button type="submit">Verify receipt</button>
    </form>
  </main>
</body>
</html>`;

  const server = createServer(async (request, response) => {
    const method = request.method || "GET";
    if (!["GET", "HEAD", "POST"].includes(method)) {
      send(
        response,
        405,
        { ...securityHeaders("text/plain; charset=utf-8"), allow: "GET, HEAD, POST" },
        "Method Not Allowed",
      );
      return;
    }

    const path = new URL(request.url || "/", `http://${host}`).pathname;
    if (path === "/") {
      if (method === "POST") {
        try {
          const chunks = [];
          for await (const chunk of request) chunks.push(Buffer.from(chunk));
          const rawBody = Buffer.concat(chunks).toString("utf8");
          const contentType = request.headers["content-type"] || "";
          const parsed = parseRequestBody(rawBody, contentType);
          let envelopeCandidate;
          if (contentType.includes("application/x-www-form-urlencoded")) {
            const formValues = parsed;
            const payload = createPayload({
              projectTitle: formValues.projectTitle || formValues.title || "",
              projectDescription:
                formValues.projectDescription || formValues.description || "",
              repositoryUrl: formValues.repositoryUrl || formValues.repo || "",
              commit: formValues.commit || "",
              cluster: formValues.cluster || "devnet",
              rpcUrl: formValues.rpcUrl || formValues.rpc,
              transactionSignature:
                formValues.transactionSignature || formValues.tx,
              programId: formValues.programId || formValues.program,
              demoUrl: formValues.demoUrl || formValues.demo,
            });
            envelopeCandidate = createEnvelope(payload);
          } else if (contentType.includes("multipart/form-data")) {
            const formValues = parsed;
            const receiptValue = formValues.receipt || formValues["receipt-file"] || "{}";
            envelopeCandidate = JSON.parse(receiptValue);
          } else {
            envelopeCandidate = parsed;
          }
          const uploadedResult = await verifyEnvelope(envelopeCandidate, { network });
          const schemaCheck = uploadedResult.checks.find(
            (check) => check.name === "schema",
          );
          if (schemaCheck?.status === "failed") {
            send(
              response,
              400,
              securityHeaders("text/plain; charset=utf-8"),
              `Invalid receipt: ${schemaCheck.message}`,
            );
            return;
          }
          const uploadedHtml = renderHtml(envelopeCandidate, uploadedResult);
          const uploadBanner = `<div style="margin: 0 0 1rem; padding: 0.9rem 1rem; border-left: 4px solid #0a7a55; background: #eefaf4; color: #10231d; border-radius: 8px; font-weight: 600;">Receipt upload</div>`;
          send(
            response,
            200,
            securityHeaders("text/html; charset=utf-8"),
            request.method === "HEAD" ? "" : `${uploadBanner}${uploadedHtml}`,
          );
          return;
        } catch (error) {
          send(
            response,
            400,
            securityHeaders("text/plain; charset=utf-8"),
            `Invalid receipt JSON: ${error.message}`,
          );
          return;
        }
      }

      send(
        response,
        200,
        securityHeaders("text/html; charset=utf-8"),
        method === "HEAD" ? "" : uploadPage,
      );
      return;
    }
    if (path === "/review") {
      if (method === "POST") {
        try {
          const chunks = [];
          for await (const chunk of request) chunks.push(Buffer.from(chunk));
          const rawBody = Buffer.concat(chunks).toString("utf8");
          const contentType = request.headers["content-type"] || "";
          const parsed = parseRequestBody(rawBody, contentType);
          const submitEnvelope =
            parsed && typeof parsed === "object" && !Array.isArray(parsed)
              ? parsed
              : JSON.parse(rawBody || "{}");
          const verificationResult = await verifyEnvelope(submitEnvelope, { network });
          const schemaCheck = verificationResult.checks.find(
            (check) => check.name === "schema",
          );
          if (schemaCheck?.status === "failed") {
            send(
              response,
              400,
              securityHeaders("text/html; charset=utf-8"),
              method === "HEAD" ? "" : `<div class="error">Invalid receipt: ${schemaCheck.message}</div>`,
            );
            return;
          }
          const verifiedHtml = renderHtml(submitEnvelope, verificationResult);
          send(
            response,
            200,
            securityHeaders("text/html; charset=utf-8"),
            method === "HEAD" ? "" : verifiedHtml,
          );
          return;
        } catch (error) {
          send(
            response,
            400,
            securityHeaders("text/html; charset=utf-8"),
            method === "HEAD" ? "" : `<div class="error">Invalid receipt: ${error.message}</div>`,
          );
          return;
        }
      }
      send(
        response,
        200,
        securityHeaders("text/html; charset=utf-8"),
        method === "HEAD" ? "" : reviewPage,
      );
      return;
    }
    if (path === "/api/receipt") {
      if (method !== "GET" && method !== "HEAD") {
        send(
          response,
          405,
          { ...securityHeaders("text/plain; charset=utf-8"), allow: "GET, HEAD" },
          "Method Not Allowed",
        );
        return;
      }
      const body = `${JSON.stringify(envelope, null, 2)}\n`;
      send(
        response,
        200,
        securityHeaders("application/json; charset=utf-8"),
        method === "HEAD" ? "" : body,
      );
      return;
    }
    if (path === "/api/verification") {
      if (method !== "GET" && method !== "HEAD") {
        send(
          response,
          405,
          { ...securityHeaders("text/plain; charset=utf-8"), allow: "GET, HEAD" },
          "Method Not Allowed",
        );
        return;
      }
      const body = `${JSON.stringify(result, null, 2)}\n`;
      send(
        response,
        200,
        securityHeaders("application/json; charset=utf-8"),
        method === "HEAD" ? "" : body,
      );
      return;
    }
    if (path === "/api/verify") {
      if (method !== "POST") {
        send(
          response,
          405,
          { ...securityHeaders("text/plain; charset=utf-8"), allow: "POST" },
          "Method Not Allowed",
        );
        return;
      }
      try {
        const chunks = [];
        for await (const chunk of request) chunks.push(Buffer.from(chunk));
        const rawBody = Buffer.concat(chunks).toString("utf8");
        const contentType = request.headers["content-type"] || "";
        const parsed = parseRequestBody(rawBody, contentType);
        const submitEnvelope = parsed && typeof parsed === "object" && !Array.isArray(parsed)
          ? parsed
          : JSON.parse(rawBody || "{}");
        const verificationResult = await verifyEnvelope(submitEnvelope, { network });
        const schemaCheck = verificationResult.checks.find(
          (check) => check.name === "schema",
        );
        if (schemaCheck?.status === "failed") {
          send(
            response,
            400,
            securityHeaders("application/json; charset=utf-8"),
            JSON.stringify({
              passed: false,
              verifiedAt: verificationResult.verifiedAt,
              checks: verificationResult.checks,
              error: schemaCheck.message,
            }),
          );
          return;
        }
        send(
          response,
          200,
          securityHeaders("application/json; charset=utf-8"),
          JSON.stringify(verificationResult, null, 2),
        );
        return;
      } catch (error) {
        send(
          response,
          400,
          securityHeaders("application/json; charset=utf-8"),
          JSON.stringify({
            passed: false,
            verifiedAt: new Date().toISOString(),
            checks: [],
            error: error.message,
          }),
        );
        return;
      }
    }
    send(
      response,
      404,
      securityHeaders("text/plain; charset=utf-8"),
      method === "HEAD" ? "" : "Not Found",
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
