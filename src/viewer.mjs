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
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
  };
}

function extractEnvelope(parsed, rawBody, contentType) {
  if (contentType.includes("application/x-www-form-urlencoded") || contentType.includes("multipart/form-data")) {
    const receiptStr = parsed?.receipt || parsed?.["receipt-file"];
    if (receiptStr && typeof receiptStr === "string") {
      try { return JSON.parse(receiptStr); } catch { /* fall through */ }
    }
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed) && !parsed.receipt) return parsed;
  }
  if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) return parsed;
  return JSON.parse(rawBody || "{}");
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
  const sharedCss = `
    @keyframes fadeUp{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
    @keyframes glow{0%,100%{box-shadow:0 0 8px rgba(20,241,149,.25)}50%{box-shadow:0 0 16px rgba(20,241,149,.45)}}
    @keyframes shimmer{0%{background-position:-200% 0}100%{background-position:200% 0}}
    :root{
      --bg:#0a0a0f;--panel:rgba(17,17,24,.92);--panel-alt:#15151e;
      --line:rgba(255,255,255,.08);--text:#f4f3f8;--muted:#92909f;
      --purple:#9945ff;--green:#14f195;
      --green-soft:rgba(20,241,149,.1);--purple-soft:rgba(153,69,255,.12);
      --shadow:0 24px 60px rgba(0,0,0,.35);
      --glow-green:0 0 20px rgba(20,241,149,.15);
      --danger:#ff6b61;
    }
    *{box-sizing:border-box;margin:0}
    html,body{min-height:100%}
    body{font-family:"Trebuchet MS",Verdana,sans-serif;color:var(--text);background:var(--bg);background-image:radial-gradient(ellipse at 20% 0%,rgba(153,69,255,.06) 0%,transparent 60%),radial-gradient(ellipse at 80% 100%,rgba(20,241,149,.04) 0%,transparent 50%)}
    .page{width:min(760px,calc(100% - 2rem));margin:2.5rem auto;animation:fadeUp .5s ease-out both}
    .shell{position:relative;overflow:hidden;padding:1.25rem;border:1px solid var(--line);border-radius:12px;background:var(--panel);backdrop-filter:blur(14px);box-shadow:var(--shadow),var(--glow-green)}
    .shell::before{content:"";position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,var(--purple),var(--green))}
    .header{display:flex;justify-content:space-between;align-items:center;gap:1rem;padding:.25rem .4rem 1.2rem;border-bottom:1px solid var(--line);margin-bottom:1.4rem}
    .brand{display:inline-flex;align-items:center;gap:.75rem;letter-spacing:.18em;text-transform:uppercase;font-size:.72rem;font-weight:800;color:var(--green);font-family:"SFMono-Regular",Consolas,monospace}
    .brand-mark{width:12px;height:12px;border-radius:3px;background:linear-gradient(135deg,var(--purple),var(--green));animation:glow 3s ease-in-out infinite}
    .brand-nav{display:flex;gap:.5rem;margin-left:auto}
    .brand-nav a{color:var(--muted);text-decoration:none;font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;padding:.35rem .65rem;border-radius:4px;border:1px solid transparent;transition:all .2s;font-family:"SFMono-Regular",Consolas,monospace}
    .brand-nav a:hover{color:var(--green);border-color:rgba(20,241,149,.2);background:var(--green-soft)}
    .brand-nav a.active{color:var(--green);border-color:rgba(20,241,149,.3);background:var(--green-soft)}
    .status-pill{display:inline-flex;align-items:center;gap:.55rem;border:1px solid rgba(20,241,149,.35);border-radius:999px;background:var(--green-soft);padding:.48rem .8rem;color:var(--green);font-size:.72rem;font-weight:800;letter-spacing:.08em;text-transform:uppercase}
    .status-dot{width:.55rem;height:.55rem;border-radius:50%;background:var(--green);box-shadow:0 0 8px rgba(20,241,149,.5)}
    .card{background:rgba(21,21,30,.85);border:1px solid var(--line);border-radius:8px;padding:1.6rem;backdrop-filter:blur(8px)}
    h1{margin:0 0 .7rem;font-family:Georgia,"Times New Roman",serif;font-size:2.8rem;line-height:1.04;letter-spacing:0;background:linear-gradient(90deg,var(--purple),var(--green));-webkit-background-clip:text;background-clip:text;color:transparent}
    .lede{margin:0 0 1.2rem;max-width:62ch;color:var(--muted);line-height:1.6}
    label{display:block;margin-bottom:.55rem;color:var(--muted);font-size:.73rem;font-weight:800;letter-spacing:.1em;text-transform:uppercase;font-family:"SFMono-Regular",Consolas,monospace}
    label .optional{color:rgba(146,144,159,.5);font-weight:400;text-transform:none;letter-spacing:0}
    textarea{width:100%;min-height:240px;margin-bottom:1rem;background:rgba(4,12,10,.72);border:1px solid rgba(154,230,255,.18);border-radius:6px;padding:1rem 1rem .95rem;resize:vertical;color:var(--text);font:.9rem/1.6 "SFMono-Regular",Consolas,"Liberation Mono",Menlo,monospace;transition:border-color .2s,box-shadow .2s}
    textarea::placeholder{color:rgba(185,217,207,.5)}
    textarea:focus{outline:none;border-color:var(--green);box-shadow:0 0 0 3px rgba(20,241,149,.12)}
    input[type="file"]{width:100%;margin-top:.2rem;color:var(--muted)}
    .button-row{display:flex;align-items:center;gap:.85rem;margin-top:.7rem}
    button{appearance:none;border:0;border-radius:6px;padding:.8rem 1.4rem;background:linear-gradient(135deg,var(--purple),#b06aff);color:#fff;font-weight:900;cursor:pointer;transition:transform .15s,box-shadow .2s;box-shadow:0 4px 16px rgba(153,69,255,.3);font-size:.9rem}
    button:hover{transform:translateY(-1px);box-shadow:0 6px 24px rgba(153,69,255,.45)}
    button:active{transform:translateY(0)}
    button.secondary{background:rgba(255,255,255,.06);box-shadow:0 2px 8px rgba(0,0,0,.2)}
    button.secondary:hover{background:rgba(255,255,255,.1)}
    .note{margin:0;color:var(--muted);line-height:1.6;font-size:.88rem}
    .steps{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:1rem;margin:1.4rem 0}
    .step{position:relative;padding:1.2rem;border:1px solid var(--line);border-radius:8px;background:rgba(10,17,14,.6);transition:border-color .2s,transform .2s}
    .step:hover{border-color:rgba(20,241,149,.2);transform:translateY(-2px)}
    .step-num{display:inline-flex;align-items:center;justify-content:center;width:1.8rem;height:1.8rem;border-radius:50%;background:linear-gradient(135deg,var(--purple),var(--green));color:#fff;font-size:.75rem;font-weight:900;margin-bottom:.7rem}
    .step strong{display:block;margin-bottom:.3rem;font-size:.95rem}
    .step span{color:var(--muted);font-size:.85rem;line-height:1.5}
    .demo-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.65rem;margin:1.2rem 0}
    .demo-btn{display:block;text-align:left;padding:.85rem 1rem;border:1px solid var(--line);border-radius:6px;background:rgba(21,21,30,.6);color:var(--text);text-decoration:none;transition:all .2s;cursor:pointer}
    .demo-btn:hover{border-color:rgba(20,241,149,.3);background:rgba(20,241,149,.05);transform:translateY(-1px)}
    .demo-btn strong{display:block;margin-bottom:.2rem;font-size:.88rem;color:var(--text)}
    .demo-btn span{font-size:.78rem;color:var(--muted)}
    .feature-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:1rem;margin:1.2rem 0 1.5rem}
    .feature{background:rgba(10,17,14,.9);border:1px solid var(--line);border-radius:6px;padding:1rem;transition:border-color .2s,transform .2s}
    .feature:hover{border-color:rgba(20,241,149,.2);transform:translateY(-2px)}
    .feature small{display:block;margin-bottom:.5rem;color:var(--green);font-weight:800;letter-spacing:.09em;text-transform:uppercase}
    .feature strong{display:block;margin-bottom:.35rem;font-size:1rem}
    .feature span{color:var(--muted);line-height:1.5;font-size:.92rem}
    .field{display:grid;gap:.45rem;margin-bottom:1rem}
    .field-hint{font-size:.78rem;color:var(--muted);margin-top:-.2rem}
    input,select{width:100%;border:1px solid var(--line);border-radius:6px;padding:.8rem;background:var(--panel-alt);color:var(--text);font:.88rem/1.5 "SFMono-Regular",Consolas,monospace;transition:border-color .2s,box-shadow .2s}
    input:focus-visible,select:focus-visible{outline:none;border-color:var(--green);box-shadow:0 0 0 3px rgba(20,241,149,.12)}
    .wide{grid-column:1/-1}
    .status-guide{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:.65rem;margin:1.2rem 0 1.5rem}
    .status-guide div{border-top:2px solid var(--green);padding:.7rem .75rem 0;background:rgba(10,17,14,.55);border-radius:0 0 6px 6px;transition:border-color .2s,transform .2s}
    .status-guide div:hover{transform:translateY(-2px)}
    .status-guide strong{display:block;margin-bottom:.25rem;font-size:.85rem}
    .status-guide span{color:var(--muted);font-size:.78rem;line-height:1.4}
    .error{color:var(--danger);font-weight:700}
    @media(max-width:760px){.page{width:min(100% - 1rem,760px);margin:1.25rem auto}.header{flex-direction:column;align-items:flex-start}.brand-nav{margin-left:0}.content{grid-template-columns:1fr}h1{font-size:2.25rem}.steps{grid-template-columns:1fr}.demo-grid{grid-template-columns:1fr}.feature-grid{grid-template-columns:1fr}.status-guide{grid-template-columns:repeat(2,minmax(0,1fr))}}
    @media(max-width:420px){.status-guide{grid-template-columns:1fr}}
  `;

  const navHtml = `<div class="brand-nav">
    <a href="/">Upload</a>
    <a href="/builder">Builder</a>
    <a href="/review">Verify</a>
  </div>`;

  const uploadPage = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="color-scheme" content="dark">
  <title>Solana Ship Receipt — Verify Build Provenance</title>
  <style>${sharedCss}</style>
</head>
<body>
  <div class="page">
    <div class="shell">
      <div class="header">
        <div class="brand"><span class="brand-mark"></span> Solana Ship Receipt</div>
        ${navHtml}
      </div>
      <div class="content" style="display:block">
        <main class="card" style="margin-bottom:1.2rem">
          <h1>Verify build provenance</h1>
          <p class="lede">A tamper-evident receipt that binds a Git commit, Solana program, and optional wallet signature into a single verifiable artifact. Paste a receipt to verify it, or start from scratch.</p>
          <div class="steps">
            <div class="step"><span class="step-num">1</span><strong>Upload or paste</strong><span>Drop a receipt JSON or paste it into the verifier.</span></div>
            <div class="step"><span class="step-num">2</span><strong>Verify evidence</strong><span>Check hash integrity, on-chain state, Git commit, and wallet signature.</span></div>
            <div class="step"><span class="step-num">3</span><strong>Share result</strong><span>Render a public receipt page or export the verification bundle.</span></div>
          </div>
          <form method="post" action="/" accept-charset="utf-8" enctype="multipart/form-data">
            <label for="receipt">Receipt JSON</label>
            <textarea id="receipt" name="receipt" placeholder="Paste your receipt JSON here...&#10;&#10;{&#10;  &quot;version&quot;: 1,&#10;  &quot;payload&quot;: { ... },&#10;  &quot;receiptHash&quot;: &quot;...&quot;&#10;}"></textarea>
            <label for="receipt-file">Or upload a file</label>
            <input id="receipt-file" type="file" name="receipt-file" accept="application/json">
            <div class="button-row">
              <button type="submit">Review receipt</button>
              <a href="/review" style="color:var(--muted);font-size:.85rem;text-decoration:none">or use the verifier page &rarr;</a>
            </div>
          </form>
        </main>
        <div class="card">
          <label style="margin-bottom:.8rem">Quick start — try a demo receipt</label>
          <div class="demo-grid">
            <button class="demo-btn" type="button" onclick="fetch('/api/receipt').then(r=>r.json()).then(j=>{document.getElementById('receipt').value=JSON.stringify(j,null,2)})"><strong>Solana Ship Receipt</strong><span>Self-referential 9/9 verified receipt</span></button>
            <a class="demo-btn" href="/review"><strong>Verifier page</strong><span>Paste JSON and get instant verification results</span></a>
            <a class="demo-btn" href="/builder"><strong>Builder flow</strong><span>Create a new receipt from project metadata</span></a>
            <a class="demo-btn" href="/api/verify" target="_blank"><strong>API endpoint</strong><span>POST JSON to get machine-readable checks</span></a>
          </div>
        </div>
      </div>
    </div>
  </div>
</body>
</html>`;

  const builderPage = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="color-scheme" content="dark">
  <title>Create receipt · Solana Ship Receipt</title>
  <style>${sharedCss}
    .fields{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1rem}
    @media(max-width:620px){.fields{grid-template-columns:1fr}.wide{grid-column:auto}}
  </style>
</head>
<body>
  <div class="page"><div class="shell">
    <div class="header">
      <div class="brand"><span class="brand-mark"></span> Solana Ship Receipt</div>
      ${navHtml}
    </div>
    <main class="card">
      <h1>Create a receipt</h1>
      <p class="lede">Bind a public Git revision to Solana program evidence. Fill in the required fields below — optional fields strengthen the receipt but aren't required.</p>
      <div class="steps" style="margin-bottom:1.5rem">
        <div class="step"><span class="step-num">1</span><strong>Fill in details</strong><span>Project name, repo URL, commit SHA, and Solana program ID.</span></div>
        <div class="step"><span class="step-num">2</span><strong>Add evidence</strong><span>Optional: demo URL, verified build, transaction signature.</span></div>
        <div class="step"><span class="step-num">3</span><strong>Sign &amp; share</strong><span>Wallet signing and memo anchoring happen locally after creation.</span></div>
      </div>
      <form method="post" action="/" accept-charset="utf-8">
        <div class="fields">
          <div class="field wide"><label for="project-title">Project title <span class="optional">(required)</span></label><input id="project-title" name="projectTitle" required minlength="3" maxlength="120" placeholder="e.g. Metaplex Token Metadata"></div>
          <div class="field wide"><label for="project-description">Description <span class="optional">(required)</span></label><textarea id="project-description" name="projectDescription" required minlength="10" maxlength="1000" placeholder="Brief description of what this project does..."></textarea></div>
          <div class="field"><label for="repository-url">Repository URL <span class="optional">(required)</span></label><input id="repository-url" name="repositoryUrl" type="url" placeholder="https://github.com/owner/project" required><div class="field-hint">Public GitHub repository URL</div></div>
          <div class="field"><label for="commit">Commit SHA <span class="optional">(required)</span></label><input id="commit" name="commit" pattern="[0-9a-fA-F]{40}" required placeholder="40-character full SHA" maxlength="40"><div class="field-hint">Full 40-character Git commit hash</div></div>
          <div class="field"><label for="cluster">Solana cluster</label><select id="cluster" name="cluster"><option value="devnet">devnet</option><option value="testnet">testnet</option><option value="mainnet">mainnet</option></select></div>
          <div class="field"><label for="program-id">Program ID <span class="optional">(optional)</span></label><input id="program-id" name="programId" placeholder="e.g. MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"><div class="field-hint">The deployed Solana program address</div></div>
          <div class="field"><label for="transaction-signature">Transaction signature <span class="optional">(optional)</span></label><input id="transaction-signature" name="transactionSignature" placeholder="Confirmed tx signature"><div class="field-hint">Evidence of on-chain deployment</div></div>
          <div class="field"><label for="demo-url">Demo URL <span class="optional">(optional)</span></label><input id="demo-url" name="demoUrl" type="url" placeholder="https://your-project.vercel.app"><div class="field-hint">Live deployment URL (must return HTTP 200)</div></div>
          <div class="field"><label for="verified-build-url">Verified-build URL <span class="optional">(optional)</span></label><input id="verified-build-url" name="verifiedBuildUrl" type="url" placeholder="https://github.com/owner/project/actions"><div class="field-hint">CI workflow proving reproducible builds</div></div>
        </div>
        <p class="note" style="margin-bottom:1rem">Wallet signing and Memo anchoring happen locally after creation. This hosted flow never requests private keys or submits transactions.</p>
        <div class="button-row">
          <button type="submit">Create receipt</button>
          <a href="/" style="color:var(--muted);font-size:.85rem;text-decoration:none">&larr; back to upload</a>
        </div>
      </form>
    </main>
  </div></div>
</body>
</html>`;

  const reviewPage = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="color-scheme" content="dark">
  <title>Verify receipt · Solana Ship Receipt</title>
  <style>${sharedCss}
    .or-divider{display:flex;align-items:center;gap:1rem;margin:1.2rem 0;color:var(--muted);font-size:.8rem;text-transform:uppercase;letter-spacing:.1em}
    .or-divider::before,.or-divider::after{content:"";flex:1;height:1px;background:var(--line)}
  </style>
</head>
<body>
  <div class="page">
    <div class="shell">
      <div class="header">
        <div class="brand"><span class="brand-mark"></span> Solana Ship Receipt</div>
        ${navHtml}
      </div>
      <main class="card">
        <h1>Verify receipt</h1>
        <p class="lede">Paste a receipt JSON below to verify its integrity, on-chain evidence, and wallet attestation. The verifier checks hash consistency, Git commit, Solana program state, demo URL, and build provenance.</p>
        <div class="status-guide" aria-label="Verification status guide">
          <div><strong style="color:var(--green)">&#10003; Verified</strong><span>Evidence matched and confirmed.</span></div>
          <div><strong style="color:var(--danger)">&#10007; Failed</strong><span>Evidence did not match.</span></div>
          <div><strong style="color:#f5a623">&#9888; Warning</strong><span>Could not complete check.</span></div>
          <div><strong style="color:var(--muted)">&mdash; Not checked</strong><span>No evidence supplied.</span></div>
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
          <textarea id="receipt" name="receipt" placeholder="Paste your receipt JSON here...&#10;&#10;{&#10;  &quot;version&quot;: 1,&#10;  &quot;payload&quot;: { ... },&#10;  &quot;receiptHash&quot;: &quot;...&quot;&#10;}"></textarea>
          <div class="button-row">
            <button type="submit">Verify receipt</button>
          </div>
        </form>
        <div class="or-divider">or try a demo</div>
        <div class="demo-grid">
          <button class="demo-btn" type="button" onclick="fetch('/api/receipt').then(r=>r.json()).then(j=>{document.getElementById('receipt').value=JSON.stringify(j,null,2);document.querySelector('form').submit()})"><strong>Solana Ship Receipt</strong><span>Load and verify the self-referential receipt (9/9)</span></button>
          <a class="demo-btn" href="/"><strong>Upload page</strong><span>Paste or upload a receipt JSON file</span></a>
          <a class="demo-btn" href="/builder"><strong>Builder flow</strong><span>Create a new receipt from scratch</span></a>
          <a class="demo-btn" href="/api/verify" target="_blank"><strong>API docs</strong><span>POST JSON to /api/verify for programmatic access</span></a>
        </div>
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
      if (requestCounts.size > 1000) {
        for (const [key, val] of requestCounts) {
          if (now - val.startedAt > rateLimit.windowMs * 2) requestCounts.delete(key);
        }
      }
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
          const uploadBanner = `<div style="margin:0 0 1rem;padding:.9rem 1rem;border-left:4px solid var(--green,#14f195);background:rgba(20,241,149,.08);color:var(--text,#f4f3f8);border-radius:8px;font-weight:600;font-family:'SFMono-Regular',Consolas,monospace;font-size:.85rem;letter-spacing:.04em">Receipt upload</div>`;
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
    if (path === "/builder") {
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
        securityHeaders("text/html; charset=utf-8"),
        method === "HEAD" ? "" : builderPage,
      );
      return;
    }
    if (path === "/review") {
      if (method === "POST") {
        try {
          const rawBody = await readRequestBody(request);
          const contentType = request.headers["content-type"] || "";
          const parsed = parseRequestBody(rawBody, contentType);
          const submitEnvelope = extractEnvelope(parsed, rawBody, contentType);
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
            securityHeaders("text/plain; charset=utf-8"),
            `Invalid receipt: ${error.message}`,
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
        const submitEnvelope = extractEnvelope(parsed, rawBody, contentType);
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
