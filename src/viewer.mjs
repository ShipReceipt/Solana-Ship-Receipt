import { createServer } from "node:http";
import {
  createEnvelope,
  createPayload,
  renderHtml,
  verifyEnvelope,
} from "./receipt.mjs";

const MAX_REQUEST_BODY_BYTES = 2 * 1024 * 1024;
const DEFAULT_RATE_LIMIT = { maxRequests: 60, windowMs: 60_000 };

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

async function readRequestBody(request) {
  const declaredLength = Number(request.headers["content-length"]);
  if (Number.isFinite(declaredLength) && declaredLength > MAX_REQUEST_BODY_BYTES) {
    const error = new Error(
      `Request body exceeds ${MAX_REQUEST_BODY_BYTES} bytes`,
    );
    error.statusCode = 413;
    throw error;
  }
  const chunks = [];
  let total = 0;
  for await (const chunk of request) {
    total += chunk.length;
    if (total > MAX_REQUEST_BODY_BYTES) {
      const error = new Error(
        `Request body exceeds ${MAX_REQUEST_BODY_BYTES} bytes`,
      );
      error.statusCode = 413;
      throw error;
    }
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks).toString("utf8");
}

export async function startViewer({
  envelope,
  port = 8787,
  host = "127.0.0.1",
  network = false,
  allowPublicHost = false,
  rateLimit = DEFAULT_RATE_LIMIT,
  maxConcurrentVerifications = 4,
  requestLogger = console,
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
  const requestCounts = new Map();
  let activeVerifications = 0;
  const verifySubmittedEnvelope = async (candidate) => {
    if (activeVerifications >= maxConcurrentVerifications) {
      const error = new Error("Verification capacity is temporarily full");
      error.statusCode = 503;
      throw error;
    }
    activeVerifications += 1;
    try {
      return await verifyEnvelope(candidate, { network });
    } finally {
      activeVerifications -= 1;
    }
  };
  const html = renderHtml(envelope, result);
  const uploadPage = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="color-scheme" content="dark">
  <title>Local viewer · Solana Ship Receipt</title>
  <style>
    :root {
      --bg: #0b0d0c;
      --panel: #111513;
      --panel-alt: #171c19;
      --line: #34413a;
      --text: #f2f4ed;
      --muted: #aeb8b0;
      --brand: #b6f23b;
      --brand-2: #d9ff91;
      --brand-soft: rgba(182, 242, 59, 0.1);
      --shadow: 0 20px 40px rgba(0, 0, 0, 0.28);
    }
    * { box-sizing: border-box; }
    html, body { margin: 0; min-height: 100%; }
    body {
      font-family: "Trebuchet MS", Verdana, sans-serif;
      color: var(--text);
      background: var(--bg);
    }
    .page {
      width: min(1080px, calc(100% - 2rem));
      margin: 4rem auto;
    }
    .shell {
      position: relative;
      overflow: hidden;
      padding: 1.25rem;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel);
      box-shadow: var(--shadow);
    }
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 1rem;
      padding: 0.25rem 0.4rem 1.2rem;
      border-bottom: 1px solid var(--line);
      margin-bottom: 1.4rem;
    }
    .brand {
      display: inline-flex;
      align-items: center;
      gap: 0.75rem;
      letter-spacing: 0.18em;
      text-transform: uppercase;
      font-size: 0.72rem;
      font-weight: 800;
      color: var(--brand);
    }
    .brand-mark {
      width: 12px;
      height: 12px;
      border-radius: 2px;
      background: var(--brand);
    }
    .status-pill {
      display: inline-flex;
      align-items: center;
      gap: 0.55rem;
      border: 1px solid rgba(20, 241, 149, 0.45);
      border-radius: 3px;
      background: var(--brand-soft);
      padding: 0.48rem 0.8rem;
      color: var(--brand);
      font-size: 0.72rem;
      font-weight: 800;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }
    .status-dot {
      width: 0.55rem;
      height: 0.55rem;
      border-radius: 50%;
      background: var(--brand);
      box-shadow: none;
    }
    .content {
      display: grid;
      grid-template-columns: minmax(0, 1.25fr) minmax(260px, 0.75fr);
      gap: 1.5rem;
      align-items: start;
      position: relative;
      z-index: 1;
    }
    .card {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 1.6rem;
    }
    h1 {
      margin: 0 0 0.7rem;
      font-family: Georgia, "Times New Roman", serif;
      font-size: 3rem;
      line-height: 1.04;
      letter-spacing: 0;
    }
    .lede {
      margin: 0 0 1.2rem;
      max-width: 62ch;
      color: var(--muted);
      line-height: 1.6;
    }
    label {
      display: block;
      margin-bottom: 0.55rem;
      color: var(--muted);
      font-size: 0.73rem;
      font-weight: 800;
      letter-spacing: 0.1em;
      text-transform: uppercase;
    }
    textarea {
      width: 100%;
      min-height: 240px;
      margin-bottom: 1rem;
      background: rgba(4, 12, 10, 0.72);
      border: 1px solid rgba(154, 230, 255, 0.18);
      border-radius: 4px;
      padding: 1rem 1rem 0.95rem;
      resize: vertical;
      color: var(--text);
      font: 0.9rem/1.6 "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
      box-shadow: none;
    }
    textarea::placeholder {
      color: rgba(185, 217, 207, 0.7);
    }
    input[type="file"] {
      width: 100%;
      margin-top: 0.2rem;
      color: var(--muted);
    }
    .button-row {
      display: flex;
      align-items: center;
      gap: 0.85rem;
      margin-top: 0.7rem;
    }
    .feature-grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 1rem;
      margin: 1.4rem 0 1.6rem;
    }
    .feature {
      background: rgba(10, 17, 14, 0.9);
      border: 1px solid var(--line);
      border-radius: 4px;
      padding: 1rem;
    }
    .feature small {
      display: block;
      margin-bottom: 0.5rem;
      color: var(--brand);
      font-weight: 800;
      letter-spacing: 0.09em;
      text-transform: uppercase;
    }
    .feature strong {
      display: block;
      margin-bottom: 0.35rem;
      font-size: 1rem;
    }
    .feature span {
      color: var(--muted);
      line-height: 1.5;
      font-size: 0.92rem;
    }
    button {
      appearance: none;
      border: 0;
      border-radius: 4px;
      padding: 0.8rem 1.1rem;
      background: var(--brand);
      color: #04120d;
      font-weight: 900;
      cursor: pointer;
      box-shadow: none;
    }
    .meta {
      display: grid;
      gap: 0.9rem;
    }
    .stat {
      border: 1px solid var(--line);
      border-radius: 4px;
      background: var(--panel-alt);
      padding: 1rem 1.1rem;
    }
    .stat strong {
      display: block;
      margin-bottom: 0.3rem;
      color: var(--brand);
      font-size: 0.72rem;
      letter-spacing: 0.1em;
      text-transform: uppercase;
    }
    .stat span {
      color: var(--muted);
      line-height: 1.5;
    }
    .note {
      margin: 0;
      color: var(--muted);
      line-height: 1.6;
    }
    @media (max-width: 760px) {
      .page { width: min(100% - 1rem, 1080px); margin: 1.25rem auto; }
      .header { flex-direction: column; align-items: flex-start; }
      .content { grid-template-columns: 1fr; }
      h1 { font-size: 2.25rem; }
    }
  </style>
</head>
<body>
  <div class="page">
    <div class="shell">
      <div class="header">
        <div class="brand"><span class="brand-mark"></span> Solana Ship Receipt</div>
        <div class="status-pill"><span class="status-dot"></span> Local viewer</div>
      </div>
      <div class="content">
        <main class="card">
          <h1>Receipt upload</h1>
          <p class="lede">Paste a canonical receipt JSON to review it in the same local viewer flow and inspect the verification result without leaving the page.</p>
          <form method="post" action="/" accept-charset="utf-8" enctype="multipart/form-data">
            <label for="receipt">Receipt JSON</label>
            <textarea id="receipt" name="receipt" placeholder="{\n  \"version\": 1,\n  \"payload\": { ... },\n  \"receiptHash\": \"...\"\n}"></textarea>
            <label for="receipt-file">Upload JSON</label>
            <input id="receipt-file" type="file" name="receipt-file" accept="application/json">
            <div class="button-row">
              <button type="submit">Review receipt</button>
            </div>
          </form>
        </main>
        <aside class="meta">
          <div class="stat"><strong>What it checks</strong><span>Receipt integrity, canonical payload hash, public evidence, and optional wallet attestation.</span></div>
          <div class="stat"><strong>Scope</strong><span>Read-only verification designed for local review and public hosting with explicit opt-in.</span></div>
          <p class="note">This viewer is intentionally loopback-safe by default and only exposes the same verification flow already used by the CLI and reviewer bundle.</p>
        </aside>
      </div>
    </div>
  </div>
</body>
</html>`;

  const reviewPage = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="color-scheme" content="dark">
  <title>Verify receipt · Solana Ship Receipt</title>
  <style>
    :root {
      --bg: #0b0d0c;
      --panel: #111513;
      --line: #34413a;
      --text: #f2f4ed;
      --muted: #aeb8b0;
      --brand: #b6f23b;
      --brand-2: #d9ff91;
      --brand-soft: rgba(182, 242, 59, 0.1);
      --shadow: 0 20px 40px rgba(0, 0, 0, 0.28);
      --danger: #ffb0ac;
    }
    * { box-sizing: border-box; }
    html, body { margin: 0; min-height: 100%; }
    body {
      font-family: "Trebuchet MS", Verdana, sans-serif;
      color: var(--text);
      background: var(--bg);
    }
    .page {
      width: min(1080px, calc(100% - 2rem));
      margin: 4rem auto;
    }
    .shell {
      position: relative;
      overflow: hidden;
      padding: 1.25rem;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel);
      box-shadow: var(--shadow);
    }
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 1rem;
      padding: 0.25rem 0.4rem 1.2rem;
      border-bottom: 1px solid var(--line);
      margin-bottom: 1.4rem;
    }
    .brand {
      display: inline-flex;
      align-items: center;
      gap: 0.75rem;
      letter-spacing: 0.18em;
      text-transform: uppercase;
      font-size: 0.72rem;
      font-weight: 800;
      color: var(--brand);
    }
    .brand-mark {
      width: 12px;
      height: 12px;
      border-radius: 2px;
      background: var(--brand);
    }
    .status-pill {
      display: inline-flex;
      align-items: center;
      gap: 0.55rem;
      border: 1px solid rgba(154, 230, 255, 0.45);
      border-radius: 3px;
      background: rgba(154, 230, 255, 0.08);
      padding: 0.48rem 0.8rem;
      color: var(--brand-2);
      font-size: 0.72rem;
      font-weight: 800;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }
    .status-dot {
      width: 0.55rem;
      height: 0.55rem;
      border-radius: 50%;
      background: var(--brand-2);
      box-shadow: none;
    }
    .card {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 1.6rem;
    }
    h1 {
      margin: 0 0 0.7rem;
      font-family: Georgia, "Times New Roman", serif;
      font-size: 3rem;
      line-height: 1.04;
      letter-spacing: 0;
    }
    .lede {
      margin: 0 0 1.2rem;
      max-width: 62ch;
      color: var(--muted);
      line-height: 1.6;
    }
    label {
      display: block;
      margin-bottom: 0.55rem;
      color: var(--muted);
      font-size: 0.73rem;
      font-weight: 800;
      letter-spacing: 0.1em;
      text-transform: uppercase;
    }
    textarea {
      width: 100%;
      min-height: 240px;
      margin-bottom: 1rem;
      background: rgba(4, 12, 10, 0.72);
      border: 1px solid rgba(154, 230, 255, 0.18);
      border-radius: 4px;
      padding: 1rem 1rem 0.95rem;
      resize: vertical;
      color: var(--text);
      font: 0.9rem/1.6 "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
      box-shadow: none;
    }
    textarea::placeholder {
      color: rgba(185, 217, 207, 0.7);
    }
    .button-row {
      display: flex;
      align-items: center;
      gap: 0.85rem;
      margin-top: 0.7rem;
    }
    .status-guide {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 0.65rem;
      margin: 1.2rem 0 1.5rem;
    }
    .status-guide div {
      border-top: 2px solid var(--brand);
      padding: 0.7rem 0.75rem 0;
      background: rgba(10, 17, 14, 0.55);
    }
    .status-guide strong {
      display: block;
      margin-bottom: 0.25rem;
      font-size: 0.85rem;
    }
    .status-guide span {
      color: var(--muted);
      font-size: 0.78rem;
      line-height: 1.4;
    }
    button {
      appearance: none;
      border: 0;
      border-radius: 4px;
      padding: 0.8rem 1.1rem;
      background: var(--brand);
      color: #04120d;
      font-weight: 900;
      cursor: pointer;
      box-shadow: none;
    }
    .error {
      color: var(--danger);
      font-weight: 700;
    }
    .note {
      margin: 0;
      color: var(--muted);
      line-height: 1.6;
    }
    @media (max-width: 760px) {
      .page { width: min(100% - 1rem, 1080px); margin: 1.25rem auto; }
      .header { flex-direction: column; align-items: flex-start; }
      .feature-grid { grid-template-columns: 1fr; }
      .status-guide { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      h1 { font-size: 2.25rem; }
    }
    @media (max-width: 420px) {
      .status-guide { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="page">
    <div class="shell">
      <div class="header">
        <div class="brand"><span class="brand-mark"></span> Solana Ship Receipt</div>
        <div class="status-pill"><span class="status-dot"></span> Verify receipt</div>
      </div>
      <main class="card">
        <h1>Verify receipt</h1>
        <p class="lede">Paste a canonical receipt JSON and submit it to the verifier API to confirm the receipt hash, schema, and public evidence.</p>
        <div class="status-guide" aria-label="Verification status guide">
          <div><strong>Verified</strong><span>Evidence matched.</span></div>
          <div><strong>Warning</strong><span>Could not complete.</span></div>
          <div><strong>Failed</strong><span>Evidence did not match.</span></div>
          <div><strong>Not checked</strong><span>No evidence supplied.</span></div>
        </div>
        <div class="feature-grid" aria-label="Evidence flow summary">
          <div class="feature">
            <small>Git commit</small>
            <strong>Immutable source</strong>
            <span>Confirms the exact repository revision and branch state used for the shipped build.</span>
          </div>
          <div class="feature">
            <small>On-chain evidence</small>
            <strong>Solana state</strong>
            <span>Checks transaction results, program identity, and public network evidence tied to the build.</span>
          </div>
          <div class="feature">
            <small>Wallet attestation</small>
            <strong>Signed identity</strong>
            <span>Validates the optional Ed25519 attestation when a builder includes wallet proof of ownership.</span>
          </div>
        </div>
        <form method="post" action="/api/verify" accept-charset="utf-8">
          <label for="receipt">Receipt JSON</label>
          <textarea id="receipt" name="receipt" placeholder="{\n  \"version\": 1,\n  \"payload\": { ... },\n  \"receiptHash\": \"...\"\n}"></textarea>
          <div class="button-row">
            <button type="submit">Verify receipt</button>
          </div>
        </form>
      </main>
    </div>
  </div>
</body>
</html>`;

  const server = createServer(async (request, response) => {
    const startedAt = Date.now();
    response.once("finish", () => {
      if (!requestLogger?.info) return;
      requestLogger.info(
        JSON.stringify({
          event: "viewer_request",
          method: request.method || "GET",
          path: new URL(request.url || "/", `http://${host}`).pathname,
          status: response.statusCode,
          durationMs: Date.now() - startedAt,
          client: request.socket.remoteAddress || "unknown",
          ...(request.verificationOutcome
            ? { verificationOutcome: request.verificationOutcome }
            : {}),
        }),
      );
    });
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
    if (method === "POST" && ["/", "/review", "/api/verify"].includes(path)) {
      const now = Date.now();
      const clientKey = request.socket.remoteAddress || "unknown";
      const current = requestCounts.get(clientKey);
      const window = current && now - current.startedAt < rateLimit.windowMs
        ? current
        : { startedAt: now, count: 0 };
      window.count += 1;
      requestCounts.set(clientKey, window);
      if (window.count > rateLimit.maxRequests) {
        const retryAfter = Math.max(
          1,
          Math.ceil((window.startedAt + rateLimit.windowMs - now) / 1000),
        );
        send(
          response,
          429,
          {
            ...securityHeaders("text/plain; charset=utf-8"),
            "retry-after": String(retryAfter),
          },
          "Too Many Requests",
        );
        return;
      }
    }
    if (path === "/health") {
      if (method !== "GET" && method !== "HEAD") {
        send(
          response,
          405,
          { ...securityHeaders("text/plain; charset=utf-8"), allow: "GET, HEAD" },
          "Method Not Allowed",
        );
        return;
      }
      send(
        response,
        200,
        securityHeaders("application/json; charset=utf-8"),
        method === "HEAD" ? "" : JSON.stringify({ status: "ok" }),
      );
      return;
    }
    if (path === "/") {
      if (method === "POST") {
        try {
          const rawBody = await readRequestBody(request);
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
          const uploadedResult = await verifySubmittedEnvelope(envelopeCandidate);
          request.verificationOutcome = uploadedResult.passed ? "passed" : "failed";
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
            error.statusCode || 400,
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
          const rawBody = await readRequestBody(request);
          const contentType = request.headers["content-type"] || "";
          const parsed = parseRequestBody(rawBody, contentType);
          const submitEnvelope =
            parsed && typeof parsed === "object" && !Array.isArray(parsed)
              ? parsed
              : JSON.parse(rawBody || "{}");
          const verificationResult = await verifySubmittedEnvelope(submitEnvelope);
          request.verificationOutcome = verificationResult.passed ? "passed" : "failed";
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
            error.statusCode || 400,
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
        const rawBody = await readRequestBody(request);
        const contentType = request.headers["content-type"] || "";
        const parsed = parseRequestBody(rawBody, contentType);
        const submitEnvelope = parsed && typeof parsed === "object" && !Array.isArray(parsed)
          ? parsed
          : JSON.parse(rawBody || "{}");
        const verificationResult = await verifySubmittedEnvelope(submitEnvelope);
        request.verificationOutcome = verificationResult.passed ? "passed" : "failed";
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
          error.statusCode || 400,
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
