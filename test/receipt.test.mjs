import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  verify as verifySignature,
} from "node:crypto";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  canonicalBytes,
  createEnvelope,
  createPayload,
  sha256,
  signEnvelope,
  verifyEnvelope,
  verifyNetwork,
} from "../src/receipt.mjs";
import { decodeBase58, encodeBase58 } from "../src/base58.mjs";

const execFileAsync = (file, args, options = {}) =>
  new Promise((resolve, reject) => {
    execFile(file, args, options, (error, stdout, stderr) => {
      if (error) {
        error.stdout = stdout;
        error.stderr = stderr;
        reject(error);
        return;
      }
      resolve({ stdout, stderr });
    });
  });

test("Base58 round-trips leading zero bytes", () => {
  const input = Buffer.from([0, 0, 1, 2, 3, 255]);
  assert.deepEqual(decodeBase58(encodeBase58(input)), input);
});

test("canonical hashes are independent of object insertion order", () => {
  const a = { z: 1, nested: { b: true, a: "x" } };
  const b = { nested: { a: "x", b: true }, z: 1 };
  assert.equal(sha256(a), sha256(b));
});

test("canonical hashes preserve empty strings and null values", () => {
  assert.notEqual(sha256({ value: "" }), sha256({}));
  assert.notEqual(sha256({ value: null }), sha256({}));
});

test("creates and locally verifies an unsigned receipt", async () => {
  const payload = createPayload({
    projectTitle: "Example",
    projectDescription: "A valid example project description.",
    repositoryUrl: "https://github.com/example/project",
    commit: "abcdef1234567890abcdef1234567890abcdef12",
  });
  const result = await verifyEnvelope(createEnvelope(payload));
  assert.equal(result.passed, true);
  assert.equal(
    result.checks.find((check) => check.name === "receipt_hash").status,
    "verified",
  );
  assert.equal(
    result.checks.find((check) => check.name === "attestation").status,
    "not_checked",
  );
});

test("signs and verifies an Ed25519 wallet attestation", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const seed = privateKey
    .export({ format: "der", type: "pkcs8" })
    .subarray(-32);
  const publicBytes = publicKey
    .export({ format: "der", type: "spki" })
    .subarray(-32);
  const dir = await mkdtemp(join(tmpdir(), "ship-receipt-"));
  const keypairPath = join(dir, "id.json");
  await writeFile(keypairPath, JSON.stringify([...seed, ...publicBytes]));
  try {
    const payload = createPayload({
      projectTitle: "Signed Example",
      projectDescription: "A valid signed example project description.",
      repositoryUrl: "https://github.com/example/project",
      commit: "abcdef1234567890abcdef1234567890abcdef12",
    });
    const signed = await signEnvelope(createEnvelope(payload), keypairPath);
    const result = await verifyEnvelope(signed);
    assert.equal(result.passed, true);
    assert.equal(
      result.checks.find((check) => check.name === "attestation").status,
      "verified",
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("tampering with payload fails hash verification", async () => {
  const payload = createPayload({
    projectTitle: "Tamper Test",
    projectDescription: "A valid tamper test project description.",
    repositoryUrl: "https://github.com/example/project",
    commit: "abcdef1234567890abcdef1234567890abcdef12",
  });
  const envelope = createEnvelope(payload);
  envelope.payload.projectTitle = "Changed";
  const result = await verifyEnvelope(envelope);
  assert.equal(result.passed, false);
  assert.equal(
    result.checks.find((check) => check.name === "receipt_hash").status,
    "failed",
  );
});

test("malformed receipts fail cleanly instead of crashing", async () => {
  const result = await verifyEnvelope({
    version: 1,
    payload: null,
    receiptHash: "bad",
  });
  assert.equal(result.passed, false);
  assert.equal(
    result.checks.find((check) => check.name === "schema").status,
    "failed",
  );
});

test("rejects malformed Solana transaction signatures and program IDs", () => {
  assert.throws(
    () =>
      createPayload({
        projectTitle: "Invalid transaction",
        projectDescription: "A project with an invalid transaction signature.",
        repositoryUrl: "https://github.com/example/project",
        commit: "abcdef1234567890abcdef1234567890abcdef12",
        transactionSignature: "not-a-solana-signature",
      }),
    /transactionSignature/,
  );
  assert.throws(
    () =>
      createPayload({
        projectTitle: "Invalid program",
        projectDescription: "A project with an invalid program address.",
        repositoryUrl: "https://github.com/example/project",
        commit: "abcdef1234567890abcdef1234567890abcdef12",
        programId: "not-a-solana-program",
      }),
    /programId/,
  );
});

test("memo anchors match the canonical payload hash without creating a self-reference", async () => {
  const fixedCreatedAt = "2026-08-27T00:00:00.000Z";
  const fixedReceiptId = "00000000-0000-4000-8000-000000000001";
  const basePayload = createPayload({
    projectTitle: "Memo matching",
    projectDescription:
      "A project used to exercise memo anchoring against the canonical receipt hash.",
    repositoryUrl: "https://github.com/example/project",
    commit: "abcdef1234567890abcdef1234567890abcdef12",
    createdAt: fixedCreatedAt,
    receiptId: fixedReceiptId,
  });
  const memoTarget = sha256({
    ...basePayload,
    solana: { ...basePayload.solana, memo: undefined },
  });
  const validPayload = createPayload({
    projectTitle: "Memo matching",
    projectDescription:
      "A project used to exercise memo anchoring against the canonical receipt hash.",
    repositoryUrl: "https://github.com/example/project",
    commit: "abcdef1234567890abcdef1234567890abcdef12",
    createdAt: fixedCreatedAt,
    receiptId: fixedReceiptId,
    memo: memoTarget,
  });
  const envelope = createEnvelope(validPayload);
  const result = await verifyEnvelope(envelope);
  assert.equal(result.passed, true);
  assert.equal(
    result.checks.find((check) => check.name === "solana_memo").status,
    "verified",
  );

  const failedPayload = createPayload({
    projectTitle: "Memo matching",
    projectDescription:
      "A project used to exercise memo anchoring against the canonical receipt hash.",
    repositoryUrl: "https://github.com/example/project",
    commit: "abcdef1234567890abcdef1234567890abcdef12",
    createdAt: fixedCreatedAt,
    receiptId: fixedReceiptId,
    memo: "deadbeef",
  });
  const failed = await verifyEnvelope(createEnvelope(failedPayload));
  assert.equal(
    failed.checks.find((check) => check.name === "solana_memo").status,
    "failed",
  );
});

test("verified-build URLs are accepted and verified when supplied", async () => {
  const payload = createPayload({
    projectTitle: "Verified build",
    projectDescription:
      "A project used to exercise verified-build evidence checks.",
    repositoryUrl: "https://github.com/example/project",
    commit: "abcdef1234567890abcdef1234567890abcdef12",
    verifiedBuildUrl: "https://www.github.com/ShipReceipt/Solana-Ship-Receipt",
  });
  const fetchImpl = async (url, init = {}) => {
    if (url.includes("api.github.com")) {
      return {
        ok: true,
        status: 200,
        headers: { get: () => null },
        json: async () => ({ sha: payload.repository.commit }),
      };
    }
    if (url.includes("github.com")) {
      return {
        ok: true,
        status: 200,
        headers: { get: () => "0" },
      };
    }
    return {
      ok: true,
      status: 200,
      headers: { get: () => null },
      json: async () => ({ result: { value: null } }),
    };
  };
  const checks = await verifyNetwork(createEnvelope(payload), { fetchImpl });
  assert.equal(
    checks.find((check) => check.name === "verified_build").status,
    "verified",
  );
});

test("network checks compare GitHub SHA and distinguish an absent account", async () => {
  const payload = createPayload({
    projectTitle: "Network checks",
    projectDescription:
      "A project used to exercise network verification behavior.",
    repositoryUrl: "https://github.com/example/project",
    commit: "abcdef1234567890abcdef1234567890abcdef12",
    programId: encodeBase58(Buffer.alloc(32, 7)),
  });
  const calls = [];
  const fetchImpl = async (url, init = {}) => {
    calls.push({ url, init });
    if (url.includes("api.github.com"))
      return {
        ok: true,
        status: 200,
        json: async () => ({ sha: "0000000000000000000000000000000000000000" }),
      };
    return {
      ok: true,
      status: 200,
      json: async () => ({ result: { value: null } }),
    };
  };
  const checks = await verifyNetwork(createEnvelope(payload), { fetchImpl });
  assert.equal(
    checks.find((check) => check.name === "github_commit").status,
    "failed",
  );
  assert.equal(
    checks.find((check) => check.name === "solana_state").status,
    "failed",
  );
  assert.equal(calls.length, 2);
});

test("program verification requires an executable account", async () => {
  const payload = createPayload({
    projectTitle: "Executable program evidence",
    projectDescription:
      "A project used to distinguish executable programs from ordinary accounts.",
    repositoryUrl: "https://github.com/example/project",
    commit: "abcdef1234567890abcdef1234567890abcdef12",
    programId: encodeBase58(Buffer.alloc(32, 8)),
  });
  const lookupImpl = async () => [{ address: "93.184.216.34", family: 4 }];
  const verifyProgram = (executable) =>
    verifyNetwork(createEnvelope(payload), {
      lookupImpl,
      fetchImpl: async (url) =>
        url.includes("api.github.com")
          ? {
              ok: true,
              status: 200,
              json: async () => ({ sha: payload.repository.commit }),
            }
          : {
              ok: true,
              status: 200,
              json: async () => ({
                result: {
                  value: {
                    executable,
                    lamports: 1,
                    owner: encodeBase58(Buffer.alloc(32, 9)),
                  },
                },
              }),
            },
    });

  const ordinaryAccount = await verifyProgram(false);
  const ordinaryCheck = ordinaryAccount.find(
    (check) => check.name === "solana_state",
  );
  assert.equal(ordinaryCheck.status, "failed");
  assert.equal(ordinaryCheck.details.executable, false);
  assert.match(ordinaryCheck.message, /executable program account/i);

  const executableProgram = await verifyProgram(true);
  const executableCheck = executableProgram.find(
    (check) => check.name === "solana_state",
  );
  assert.equal(executableCheck.status, "verified");
  assert.equal(executableCheck.details.executable, true);
});

test("demo verification falls back from HEAD to GET when HEAD is unsupported", async () => {
  const payload = createPayload({
    projectTitle: "Demo fallback",
    projectDescription:
      "A project used to exercise demo availability behavior.",
    repositoryUrl: "https://github.com/example/project",
    commit: "abcdef1234567890abcdef1234567890abcdef12",
    demoUrl: "https://demo.example.com/receipt",
  });
  const methods = [];
  const fetchImpl = async (url, init = {}) => {
    if (url.includes("api.github.com"))
      return {
        ok: true,
        status: 200,
        json: async () => ({ sha: "abcdef1234567890abcdef1234567890abcdef12" }),
      };
    methods.push(init.method || "GET");
    return methods.at(-1) === "HEAD"
      ? { ok: false, status: 405, json: async () => ({}) }
      : { ok: true, status: 200, json: async () => ({}) };
  };
  const lookupImpl = async () => [{ address: "93.184.216.34", family: 4 }];
  const checks = await verifyNetwork(createEnvelope(payload), {
    fetchImpl,
    lookupImpl,
  });
  assert.equal(
    checks.find((check) => check.name === "demo_url").status,
    "verified",
  );
  assert.deepEqual(methods, ["HEAD", "GET"]);
});

test("rejects private, loopback, and credentialed outbound URLs", () => {
  const base = {
    projectTitle: "URL safety",
    projectDescription: "A project used to exercise outbound URL safety.",
    repositoryUrl: "https://github.com/example/project",
    commit: "abcdef1234567890abcdef1234567890abcdef12",
  };
  assert.throws(
    () => createPayload({ ...base, rpcUrl: "http://10.0.0.8/rpc" }),
    /rpcUrl/,
  );
  assert.throws(
    () => createPayload({ ...base, rpcUrl: "http://169.254.169.254/latest" }),
    /rpcUrl/,
  );
  assert.throws(
    () => createPayload({ ...base, demoUrl: "http://[::1]/demo" }),
    /demoUrl/,
  );
  assert.throws(
    () =>
      createPayload({
        ...base,
        repositoryUrl: "https://user:password@github.com/example/project",
      }),
    /repository.url/,
  );
});

test("rejects reserved and IPv4-mapped network destinations", () => {
  const base = {
    projectTitle: "Reserved URL safety",
    projectDescription:
      "A project used to reject non-public network destinations.",
    repositoryUrl: "https://github.com/example/project",
    commit: "abcdef1234567890abcdef1234567890abcdef12",
  };
  assert.throws(
    () => createPayload({ ...base, rpcUrl: "http://100.64.0.1/rpc" }),
    /rpcUrl/,
  );
  assert.throws(
    () => createPayload({ ...base, demoUrl: "http://[::ffff:127.0.0.1]/demo" }),
    /demoUrl/,
  );
  assert.throws(
    () => createPayload({ ...base, demoUrl: "http://[::127.0.0.1]/demo" }),
    /demoUrl/,
  );
  assert.throws(
    () => createPayload({ ...base, demoUrl: "https://192.0.2.10/demo" }),
    /demoUrl/,
  );
});

test("runtime validation rejects schema extensions and malformed metadata", async () => {
  const payload = createPayload({
    projectTitle: "Strict runtime schema",
    projectDescription:
      "A project used to keep runtime validation aligned with the JSON Schema.",
    repositoryUrl: "https://github.com/example/project",
    commit: "abcdef1234567890abcdef1234567890abcdef12",
  });
  const extended = createEnvelope(payload);
  extended.payload.unexpected = true;
  extended.receiptHash = sha256(extended.payload);
  const extendedResult = await verifyEnvelope(extended);
  assert.equal(extendedResult.passed, false);
  assert.equal(
    extendedResult.checks.find((check) => check.name === "schema").status,
    "failed",
  );

  assert.throws(
    () =>
      createPayload({
        projectTitle: "Invalid metadata",
        projectDescription:
          "A project with invalid timestamp and identifier metadata.",
        repositoryUrl: "https://github.com/example/project",
        commit: "abcdef1234567890abcdef1234567890abcdef12",
        createdAt: "not-a-timestamp",
        receiptId: "not-a-uuid",
      }),
    /createdAt|receiptId/,
  );

  assert.throws(
    () =>
      createPayload({
        projectTitle: "Invalid calendar date",
        projectDescription:
          "A project used to reject impossible RFC 3339 calendar dates.",
        repositoryUrl: "https://github.com/example/project",
        commit: "abcdef1234567890abcdef1234567890abcdef12",
        createdAt: "2026-02-31T00:00:00Z",
      }),
    /createdAt/,
  );

  assert.throws(
    () =>
      createPayload({
        projectTitle: "Invalid repository path",
        projectDescription:
          "A project whose repository URL points to an issue rather than a repository.",
        repositoryUrl: "https://github.com/example/project/issues/1",
        commit: "abcdef1234567890abcdef1234567890abcdef12",
      }),
    /repository.url/,
  );

  assert.throws(
    () =>
      createPayload({
        projectTitle: "Insecure repository URL",
        projectDescription:
          "A project whose repository URL does not use encrypted transport.",
        repositoryUrl: "http://github.com/example/project",
        commit: "abcdef1234567890abcdef1234567890abcdef12",
      }),
    /repository.url must use https/,
  );

  assert.throws(
    () =>
      createPayload({
        projectTitle: "Custom repository port",
        projectDescription:
          "A project whose repository URL uses an unsupported custom port.",
        repositoryUrl: "https://github.com:8443/example/project",
        commit: "abcdef1234567890abcdef1234567890abcdef12",
      }),
    /repository.url must not use a custom port/,
  );

  assert.throws(
    () =>
      createPayload({
        projectTitle: "Empty required option",
        projectDescription:
          "A project used to reject empty values for required metadata.",
        repositoryUrl: "https://github.com/example/project",
        commit: "abcdef1234567890abcdef1234567890abcdef12",
        cluster: "",
        rpcUrl: "",
        createdAt: "",
        receiptId: "",
      }),
    /solana.cluster|rpcUrl|createdAt|receiptId/,
  );
});

test("rejects unsupported envelope versions and attestation algorithms", async () => {
  const payload = createPayload({
    projectTitle: "Envelope contract",
    projectDescription:
      "A project used to exercise envelope compatibility checks.",
    repositoryUrl: "https://github.com/example/project",
    commit: "abcdef1234567890abcdef1234567890abcdef12",
  });
  const unsupported = await verifyEnvelope({
    version: 2,
    payload,
    receiptHash: sha256(payload),
  });
  assert.equal(unsupported.passed, false);
  assert.equal(
    unsupported.checks.find((check) => check.name === "version").status,
    "failed",
  );

  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const seed = privateKey
    .export({ format: "der", type: "pkcs8" })
    .subarray(-32);
  const publicBytes = publicKey
    .export({ format: "der", type: "spki" })
    .subarray(-32);
  const dir = await mkdtemp(join(tmpdir(), "ship-receipt-"));
  const keypairPath = join(dir, "id.json");
  await writeFile(keypairPath, JSON.stringify([...seed, ...publicBytes]));
  try {
    const signed = await signEnvelope(createEnvelope(payload), keypairPath);
    signed.attestation.algorithm = "RSA";
    const result = await verifyEnvelope(signed);
    assert.equal(result.passed, false);
    assert.equal(
      result.checks.find((check) => check.name === "attestation").status,
      "failed",
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("CLI verify --json emits a machine-readable result", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ship-receipt-cli-"));
  const receiptPath = join(dir, "receipt.json");
  try {
    const payload = createPayload({
      projectTitle: "CLI JSON",
      projectDescription:
        "A project used to exercise machine-readable verification.",
      repositoryUrl: "https://github.com/example/project",
      commit: "abcdef1234567890abcdef1234567890abcdef12",
    });
    await writeFile(
      receiptPath,
      `${JSON.stringify(createEnvelope(payload))}\n`,
    );
    const result = await execFileAsync(
      process.execPath,
      ["src/cli.mjs", "verify", receiptPath, "--json"],
      { cwd: join(process.cwd()) },
    );
    const parsed = JSON.parse(result.stdout);
    assert.equal(parsed.passed, true);
    assert.equal(
      parsed.checks.find((check) => check.name === "receipt_hash").status,
      "verified",
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("GitHub Actions workflow exposes a reproducible network verification job", async () => {
  const workflow = await readFile(
    join(process.cwd(), ".github", "workflows", "verify-receipt.yml"),
    "utf8",
  );
  assert.match(workflow, /actions\/checkout@[0-9a-f]{40} # v4/);
  assert.match(workflow, /actions\/setup-node@[0-9a-f]{40} # v4/);
  assert.match(workflow, /persist-credentials: false/);
  assert.match(workflow, /timeout-minutes: 10/);
  assert.match(workflow, /npm ci --ignore-scripts --no-audit --no-fund/);
  assert.match(workflow, /npm run check:syntax/);
  assert.match(workflow, /npm test/);
  assert.match(workflow, /node src\/cli\.mjs create/);
  assert.match(workflow, /node src\/cli\.mjs verify/);
  assert.match(workflow, /node src\/cli\.mjs bundle/);
  assert.match(workflow, /node src\/cli\.mjs audit/);
  assert.match(workflow, /--network/);
  assert.match(workflow, /--json/);
  assert.match(workflow, /reviewer-bundle/);
  assert.match(workflow, /bundle-audit\.json/);
  assert.match(workflow, /actions\/upload-artifact@[0-9a-f]{40} # v4/);
});

test("CI runs tests and package checks across supported Node versions", async () => {
  const workflow = await readFile(
    join(process.cwd(), ".github", "workflows", "ci.yml"),
    "utf8",
  );
  assert.match(workflow, /pull_request:/);
  assert.match(workflow, /node-version:\s*\n\s*- 20\s*\n\s*- 22\s*\n\s*- 24/);
  assert.match(workflow, /actions\/checkout@[0-9a-f]{40} # v4/);
  assert.match(workflow, /actions\/setup-node@[0-9a-f]{40} # v4/);
  assert.match(workflow, /persist-credentials: false/);
  assert.match(workflow, /timeout-minutes: 10/);
  assert.match(workflow, /npm ci --ignore-scripts --no-audit --no-fund/);
  assert.match(workflow, /npm run check:syntax/);
  assert.match(workflow, /npm test/);
  assert.match(workflow, /npm pack --dry-run --json/);
});

test("package metadata exposes the canonical repository and quality gate", async () => {
  const packageMetadata = JSON.parse(
    await readFile(join(process.cwd(), "package.json"), "utf8"),
  );
  assert.equal(
    packageMetadata.repository.url,
    "git+https://github.com/ShipReceipt/Solana-Ship-Receipt.git",
  );
  assert.equal(
    packageMetadata.homepage,
    "https://github.com/ShipReceipt/Solana-Ship-Receipt#readme",
  );
  assert.match(packageMetadata.scripts.check, /check:syntax/);
  assert.match(packageMetadata.scripts.check, /npm test/);
  assert.match(packageMetadata.scripts.check, /npm pack --dry-run --json/);
  const lockfile = JSON.parse(
    await readFile(join(process.cwd(), "package-lock.json"), "utf8"),
  );
  assert.equal(lockfile.lockfileVersion, 3);
  assert.equal(lockfile.packages[""].name, packageMetadata.name);
  assert.deepEqual(lockfile.packages[""].bin, packageMetadata.bin);
});

test("GitHub verification normalizes a case-insensitive clone suffix", async () => {
  const payload = createPayload({
    projectTitle: "Clone URL normalization",
    projectDescription:
      "A project used to normalize GitHub clone suffixes before API verification.",
    repositoryUrl: "https://github.com/example/project.GIT",
    commit: "abcdef1234567890abcdef1234567890abcdef12",
  });
  let requestedUrl;
  const checks = await verifyNetwork(createEnvelope(payload), {
    lookupImpl: async () => [{ address: "93.184.216.34", family: 4 }],
    fetchImpl: async (url) => {
      requestedUrl = url;
      return {
        ok: true,
        status: 200,
        json: async () => ({ sha: payload.repository.commit }),
      };
    },
  });
  assert.equal(
    checks.find((check) => check.name === "github_commit").status,
    "verified",
  );
  assert.match(requestedUrl, /\/repos\/example\/project\/commits\//);
  assert.doesNotMatch(requestedUrl, /project\.GIT/);
});

test("network verification refuses hostnames that resolve to private addresses", async () => {
  const payload = createPayload({
    projectTitle: "DNS safety",
    projectDescription:
      "A project used to exercise DNS-based outbound request safety.",
    repositoryUrl: "https://github.com/example/project",
    commit: "abcdef1234567890abcdef1234567890abcdef12",
    demoUrl: "https://internal.example.test/demo",
  });
  const fetched = [];
  const fetchImpl = async (url) => {
    fetched.push(url);
    return {
      ok: true,
      status: 200,
      json: async () => ({ sha: "abcdef1234567890abcdef1234567890abcdef12" }),
    };
  };
  const lookupImpl = async (hostname) =>
    hostname === "internal.example.test"
      ? [{ address: "127.0.0.1", family: 4 }]
      : [{ address: "93.184.216.34", family: 4 }];
  const checks = await verifyNetwork(createEnvelope(payload), {
    fetchImpl,
    lookupImpl,
  });
  assert.equal(
    checks.find((check) => check.name === "demo_url").status,
    "failed",
  );
  assert.equal(
    fetched.some((url) => url.includes("internal.example.test")),
    false,
  );
});

test("network verification is skipped when local receipt integrity fails", async () => {
  const payload = createPayload({
    projectTitle: "Local integrity gate",
    projectDescription:
      "A project used to ensure untrusted receipts cannot trigger outbound verification.",
    repositoryUrl: "https://github.com/example/project",
    commit: "abcdef1234567890abcdef1234567890abcdef12",
    demoUrl: "https://demo.example.test/receipt",
  });
  const envelope = createEnvelope(payload);
  envelope.payload.projectDescription = "Tampered after hashing.";
  const calls = [];
  const result = await verifyEnvelope(envelope, {
    network: true,
    fetchImpl: async (url) => {
      calls.push(url);
      return { ok: true, status: 200, json: async () => ({}) };
    },
    lookupImpl: async () => [{ address: "93.184.216.34", family: 4 }],
  });
  assert.equal(result.passed, false);
  assert.equal(calls.length, 0);
  assert.equal(
    result.checks.find((check) => check.name === "github_commit").status,
    "not_checked",
  );
  assert.match(
    result.checks.find((check) => check.name === "github_commit").message,
    /integrity/i,
  );
});

test("direct network verification requires local receipt integrity", async () => {
  const payload = createPayload({
    projectTitle: "Direct network gate",
    projectDescription:
      "A project used to enforce local integrity at the exported network API boundary.",
    repositoryUrl: "https://github.com/example/project",
    commit: "abcdef1234567890abcdef1234567890abcdef12",
  });
  const envelope = createEnvelope(payload);
  envelope.payload.projectTitle = "Tampered direct call";
  const calls = [];
  await assert.rejects(
    verifyNetwork(envelope, {
      fetchImpl: async (url) => {
        calls.push(url);
        return { ok: true, status: 200, json: async () => ({}) };
      },
      lookupImpl: async () => [{ address: "93.184.216.34", family: 4 }],
    }),
    /valid local receipt hash/i,
  );
  assert.equal(calls.length, 0);
});

test("network verification rejects oversized JSON responses before parsing", async () => {
  const payload = createPayload({
    projectTitle: "Bounded network response",
    projectDescription:
      "A project used to enforce bounded parsing of external verification responses.",
    repositoryUrl: "https://github.com/example/project",
    commit: "abcdef1234567890abcdef1234567890abcdef12",
  });
  let parsed = false;
  const fetchImpl = async () => ({
    ok: true,
    status: 200,
    headers: { get: (name) => (name === "content-length" ? "999999" : null) },
    json: async () => {
      parsed = true;
      return { sha: payload.repository.commit };
    },
  });
  const checks = await verifyNetwork(createEnvelope(payload), {
    fetchImpl,
    lookupImpl: async () => [{ address: "93.184.216.34", family: 4 }],
  });
  assert.equal(
    checks.find((check) => check.name === "github_commit").status,
    "warning",
  );
  assert.match(
    checks.find((check) => check.name === "github_commit").message,
    /exceeded/i,
  );
  assert.equal(parsed, false);
});

test("requires a full 40-character Git commit SHA", () => {
  assert.throws(
    () =>
      createPayload({
        projectTitle: "Exact commit",
        projectDescription:
          "A project used to require an exact immutable Git commit.",
        repositoryUrl: "https://github.com/example/project",
        commit: "abcdef1",
      }),
    /40-character/,
  );
});

test("wallet signatures are domain-separated from the raw JSON payload", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const seed = privateKey
    .export({ format: "der", type: "pkcs8" })
    .subarray(-32);
  const publicBytes = publicKey
    .export({ format: "der", type: "spki" })
    .subarray(-32);
  const dir = await mkdtemp(join(tmpdir(), "ship-receipt-domain-"));
  const keypairPath = join(dir, "id.json");
  await writeFile(keypairPath, JSON.stringify([...seed, ...publicBytes]));
  try {
    const payload = createPayload({
      projectTitle: "Domain separation",
      projectDescription:
        "A project used to exercise wallet signature domain separation.",
      repositoryUrl: "https://github.com/example/project",
      commit: "abcdef1234567890abcdef1234567890abcdef12",
    });
    const signed = await signEnvelope(createEnvelope(payload), keypairPath);
    const publicKeyObject = createPublicKey({
      key: Buffer.concat([
        Buffer.from("302a300506032b6570032100", "hex"),
        decodeBase58(signed.attestation.publicKey),
      ]),
      format: "der",
      type: "spki",
    });
    const rawPayloadIsValid = verifySignature(
      null,
      canonicalBytes(payload),
      publicKeyObject,
      decodeBase58(signed.attestation.signature),
    );
    assert.equal(rawPayloadIsValid, false);
    assert.equal(signed.attestation.context, "solana-ship-receipt/v1");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("demo checks follow validated public redirects and stop before private redirects", async () => {
  const publicPayload = createPayload({
    projectTitle: "Public redirect",
    projectDescription:
      "A project used to exercise safe public demo redirects.",
    repositoryUrl: "https://github.com/example/project",
    commit: "abcdef1234567890abcdef1234567890abcdef12",
    demoUrl: "https://demo.example.test/start",
  });
  const publicCalls = [];
  const publicFetch = async (url, init = {}) => {
    publicCalls.push({ url, method: init.method });
    if (url.includes("api.github.com"))
      return {
        ok: true,
        status: 200,
        json: async () => ({ sha: "abcdef1234567890abcdef1234567890abcdef12" }),
      };
    if (url.includes("/start"))
      return {
        ok: false,
        status: 302,
        headers: { get: () => "https://cdn.example.test/receipt" },
      };
    return { ok: true, status: 200, headers: { get: () => null } };
  };
  const publicLookup = async () => [{ address: "93.184.216.34", family: 4 }];
  const publicChecks = await verifyNetwork(createEnvelope(publicPayload), {
    fetchImpl: publicFetch,
    lookupImpl: publicLookup,
  });
  assert.equal(
    publicChecks.find((check) => check.name === "demo_url").status,
    "verified",
  );
  assert.equal(
    publicCalls.filter(
      (call) =>
        call.url.includes("example.test") ||
        call.url.includes("cdn.example.test"),
    ).length,
    2,
  );

  const privatePayload = createPayload({
    projectTitle: "Private redirect",
    projectDescription:
      "A project used to reject private demo redirect destinations.",
    repositoryUrl: "https://github.com/example/project",
    commit: "abcdef1234567890abcdef1234567890abcdef12",
    demoUrl: "https://demo.example.test/private-redirect",
  });
  const privateCalls = [];
  const privateFetch = async (url, init = {}) => {
    privateCalls.push({ url, method: init.method });
    if (url.includes("api.github.com"))
      return {
        ok: true,
        status: 200,
        json: async () => ({ sha: "abcdef1234567890abcdef1234567890abcdef12" }),
      };
    return {
      ok: false,
      status: 302,
      headers: { get: () => "http://127.0.0.1/private" },
    };
  };
  const privateChecks = await verifyNetwork(createEnvelope(privatePayload), {
    fetchImpl: privateFetch,
    lookupImpl: publicLookup,
  });
  assert.equal(
    privateChecks.find((check) => check.name === "demo_url").status,
    "failed",
  );
  assert.equal(
    privateCalls.some((call) => call.url.includes("127.0.0.1")),
    false,
  );
});

test("verification results and rendered receipts include the verification time", async () => {
  const payload = createPayload({
    projectTitle: "Verification time",
    projectDescription: "A project used to timestamp verification evidence.",
    repositoryUrl: "https://github.com/example/project",
    commit: "abcdef1234567890abcdef1234567890abcdef12",
  });
  const envelope = createEnvelope(payload);
  const result = await verifyEnvelope(envelope, {
    now: () => new Date("2026-08-23T12:34:56.000Z"),
  });
  assert.equal(result.verifiedAt, "2026-08-23T12:34:56.000Z");
  const { renderHtml } = await import("../src/receipt.mjs");
  const html = renderHtml(envelope, result);
  assert.match(html, /2026-08-23T12:34:56\.000Z/);
  assert.match(
    html,
    /<title>Verification time · Verification Receipt<\/title>/,
  );
  assert.match(html, /<meta name="color-scheme" content="light dark">/);
  assert.match(html, /<caption>Verification checks<\/caption>/);
  assert.match(html, /class="status-badge verified"/);
  assert.match(html, /aria-live="polite"/);
  assert.match(html, /<time datetime="2026-08-23T12:34:56\.000Z">/);
  assert.match(html, /rel="noreferrer noopener"/);
  assert.doesNotMatch(html, /gradient\(/i);
  assert.doesNotMatch(html, /font-size:[^;]*vw/i);
  assert.doesNotMatch(html, /letter-spacing:-/i);
});

test("rendered commit links normalize Git clone suffixes", async () => {
  const payload = createPayload({
    projectTitle: "Normalized commit link",
    projectDescription:
      "A project used to keep reviewer commit links navigable for clone URLs.",
    repositoryUrl: "https://github.com/example/project.git",
    commit: "abcdef1234567890abcdef1234567890abcdef12",
  });
  const envelope = createEnvelope(payload);
  const result = await verifyEnvelope(envelope);
  const { renderHtml } = await import("../src/receipt.mjs");
  const html = renderHtml(envelope, result);
  assert.match(
    html,
    /https:\/\/github\.com\/example\/project\/commit\/abcdef1234567890abcdef1234567890abcdef12/,
  );
  assert.doesNotMatch(html, /project\.git\/commit/);
});

test("CLI exposes its version for reviewers and automation", async () => {
  const result = await execFileAsync(
    process.execPath,
    ["src/cli.mjs", "--version"],
    { cwd: process.cwd() },
  );
  assert.match(result.stdout.trim(), /^solana-ship-receipt v0\.1\.0$/);
});

test("CLI help gives newcomers a complete first-run path", async () => {
  const result = await execFileAsync(
    process.execPath,
    ["src/cli.mjs", "--help"],
    { cwd: process.cwd() },
  );
  assert.match(result.stdout, /First run \(from this repository\)/);
  assert.match(result.stdout, /sample --out first\.receipt\.json/);
  assert.match(result.stdout, /verify first\.receipt\.json/);
  assert.match(result.stdout, /render first\.receipt\.json/);
  assert.match(result.stdout, /full 40-character Git SHA/);
  assert.match(result.stdout, /write-once/);
  assert.match(result.stdout, /docs\/GETTING-STARTED\.md/);
});

test("CLI sample uses a deterministic public fixture", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ship-receipt-sample-"));
  const firstPath = join(dir, "first.json");
  const secondPath = join(dir, "second.json");
  try {
    await execFileAsync(
      process.execPath,
      ["src/cli.mjs", "sample", "--out", firstPath],
      { cwd: process.cwd() },
    );
    await execFileAsync(
      process.execPath,
      ["src/cli.mjs", "sample", "--out", secondPath],
      { cwd: process.cwd() },
    );
    const first = JSON.parse(await readFile(firstPath, "utf8"));
    const second = JSON.parse(await readFile(secondPath, "utf8"));
    const fixture = JSON.parse(
      await readFile(
        join(
          process.cwd(),
          "fixtures",
          "public-projects",
          "metaplex-token-metadata.json",
        ),
        "utf8",
      ),
    );
    assert.deepEqual(first, second);
    assert.deepEqual(first, fixture);
    assert.equal(
      first.payload.repository.url,
      "https://github.com/metaplex-foundation/mpl-token-metadata",
    );
    assert.equal(
      first.payload.repository.commit,
      "349e061053c6fc5b6b815e03e896e4db57012893",
    );
    assert.equal(first.payload.receiptId, "00000000-0000-4000-8000-000000000002");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("CLI rejects unknown options instead of silently ignoring typos", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ship-receipt-cli-options-"));
  const receiptPath = join(dir, "receipt.json");
  try {
    const payload = createPayload({
      projectTitle: "CLI option safety",
      projectDescription:
        "A receipt used to verify unknown command options fail loudly.",
      repositoryUrl: "https://github.com/example/project",
      commit: "abcdef1234567890abcdef1234567890abcdef12",
    });
    await writeFile(
      receiptPath,
      `${JSON.stringify(createEnvelope(payload), null, 2)}\n`,
    );
    await assert.rejects(
      execFileAsync(
        process.execPath,
        ["src/cli.mjs", "verify", receiptPath, "--jso"],
        { cwd: process.cwd() },
      ),
      (error) => /Unknown option --jso/.test(error.stderr),
    );
    await assert.rejects(
      execFileAsync(
        process.execPath,
        ["src/cli.mjs", "verify", receiptPath, "--json", "--json"],
        { cwd: process.cwd() },
      ),
      (error) => /Duplicate option --json/.test(error.stderr),
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("CLI sign preserves the unsigned source by default", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const seed = privateKey
    .export({ format: "der", type: "pkcs8" })
    .subarray(-32);
  const publicBytes = publicKey
    .export({ format: "der", type: "spki" })
    .subarray(-32);
  const dir = await mkdtemp(join(tmpdir(), "ship-receipt-sign-output-"));
  const keypairPath = join(dir, "id.json");
  const receiptPath = join(dir, "receipt.json");
  const signedPath = join(dir, "receipt.signed.json");
  try {
    const payload = createPayload({
      projectTitle: "Safe signing output",
      projectDescription:
        "Signing should create a sibling artifact and preserve the unsigned source receipt.",
      repositoryUrl: "https://github.com/example/project",
      commit: "abcdef1234567890abcdef1234567890abcdef12",
    });
    const envelope = createEnvelope(payload);
    await writeFile(keypairPath, JSON.stringify([...seed, ...publicBytes]));
    await writeFile(receiptPath, `${JSON.stringify(envelope, null, 2)}\n`);
    const command = await execFileAsync(
      process.execPath,
      ["src/cli.mjs", "sign", receiptPath, "--keypair", keypairPath],
      { cwd: process.cwd() },
    );
    assert.match(command.stdout, /source preserved/i);
    assert.equal(
      await readFile(receiptPath, "utf8"),
      `${JSON.stringify(envelope, null, 2)}\n`,
    );
    const signed = JSON.parse(await readFile(signedPath, "utf8"));
    assert.equal(signed.receiptHash, envelope.receiptHash);
    assert.equal(signed.attestation.algorithm, "Ed25519");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("CLI sign refuses to replace an existing signed artifact", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const seed = privateKey
    .export({ format: "der", type: "pkcs8" })
    .subarray(-32);
  const publicBytes = publicKey
    .export({ format: "der", type: "spki" })
    .subarray(-32);
  const dir = await mkdtemp(join(tmpdir(), "ship-receipt-sign-immutable-"));
  const keypairPath = join(dir, "id.json");
  const receiptPath = join(dir, "receipt.json");
  const signedPath = join(dir, "receipt.signed.json");
  try {
    await writeFile(keypairPath, JSON.stringify([...seed, ...publicBytes]));
    const payload = createPayload({
      projectTitle: "Immutable signing",
      projectDescription:
        "A project used to ensure signed artifacts are immutable.",
      repositoryUrl: "https://github.com/example/project",
      commit: "abcdef1234567890abcdef1234567890abcdef12",
    });
    await writeFile(
      receiptPath,
      `${JSON.stringify(createEnvelope(payload))}\n`,
    );
    await execFileAsync(
      process.execPath,
      ["src/cli.mjs", "sign", receiptPath, "--keypair", keypairPath],
      { cwd: process.cwd() },
    );
    const firstArtifact = await readFile(signedPath, "utf8");
    await assert.rejects(
      execFileAsync(
        process.execPath,
        ["src/cli.mjs", "sign", receiptPath, "--keypair", keypairPath],
        { cwd: process.cwd() },
      ),
      (error) => /already exists|refusing to replace/i.test(error.stderr),
    );
    assert.equal(await readFile(signedPath, "utf8"), firstArtifact);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("CLI render preserves its source and refuses to replace existing output", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ship-receipt-render-output-"));
  const extensionlessPath = join(dir, "receipt");
  const derivedHtmlPath = join(dir, "receipt.html");
  try {
    const payload = createPayload({
      projectTitle: "Safe rendering",
      projectDescription:
        "A project used to ensure HTML rendering cannot overwrite evidence.",
      repositoryUrl: "https://github.com/example/project",
      commit: "abcdef1234567890abcdef1234567890abcdef12",
    });
    const source = `${JSON.stringify(createEnvelope(payload), null, 2)}\n`;
    await writeFile(extensionlessPath, source);
    await execFileAsync(
      process.execPath,
      ["src/cli.mjs", "render", extensionlessPath],
      { cwd: process.cwd() },
    );
    assert.equal(await readFile(extensionlessPath, "utf8"), source);
    assert.match(await readFile(derivedHtmlPath, "utf8"), /Safe rendering/);

    await assert.rejects(
      execFileAsync(
        process.execPath,
        ["src/cli.mjs", "render", extensionlessPath],
        { cwd: process.cwd() },
      ),
      (error) => /already exists|refusing to replace/i.test(error.stderr),
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("CLI create refuses to replace an existing receipt", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ship-receipt-create-output-"));
  const outputPath = join(dir, "receipt.json");
  try {
    await writeFile(outputPath, "existing evidence\n");
    await assert.rejects(
      execFileAsync(
        process.execPath,
        [
          "src/cli.mjs",
          "create",
          "--title",
          "Immutable create output",
          "--description",
          "A project used to ensure receipt creation preserves existing evidence.",
          "--repo",
          "https://github.com/example/project",
          "--commit",
          "abcdef1234567890abcdef1234567890abcdef12",
          "--out",
          outputPath,
        ],
        { cwd: process.cwd() },
      ),
      (error) => /refusing to replace/i.test(error.stderr),
    );
    assert.equal(await readFile(outputPath, "utf8"), "existing evidence\n");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("CLI rejects unexpected positional arguments", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ship-receipt-cli-positionals-"));
  const receiptPath = join(dir, "receipt.json");
  try {
    const payload = createPayload({
      projectTitle: "CLI positional safety",
      projectDescription:
        "A project used to ensure accidental positional arguments fail loudly.",
      repositoryUrl: "https://github.com/example/project",
      commit: "abcdef1234567890abcdef1234567890abcdef12",
    });
    await writeFile(
      receiptPath,
      `${JSON.stringify(createEnvelope(payload), null, 2)}\n`,
    );
    await assert.rejects(
      execFileAsync(
        process.execPath,
        ["src/cli.mjs", "verify", receiptPath, "unexpected"],
        { cwd: process.cwd() },
      ),
      (error) => /unexpected positional argument/i.test(error.stderr),
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("threat model documents the security boundaries required before hosting", async () => {
  const threatModel = await readFile(
    join(process.cwd(), "docs", "THREAT-MODEL.md"),
    "utf8",
  );
  for (const required of [
    "## Assets",
    "## Trust boundaries",
    "## Threats and mitigations",
    "SSRF",
    "private key",
    "redirect",
    "replay",
    "RPC",
    "## Non-goals",
    "## Hosted-service release gates",
  ])
    assert.match(threatModel, new RegExp(required, "i"));
});

test("getting started guide covers first use and reviewer handoff", async () => {
  const guide = await readFile(
    join(process.cwd(), "docs", "GETTING-STARTED.md"),
    "utf8",
  );
  for (const required of [
    "npm ci",
    "sample --out first.receipt.json",
    "git rev-parse HEAD",
    "FULL_40_CHARACTER_COMMIT_SHA",
    "verify my-project.receipt.json --network",
    "bundle my-project.receipt.json",
    "audit reviewer-bundle --json",
    "not_checked",
    "Common problems",
  ])
    assert.match(guide, new RegExp(required.replaceAll(".", "\\."), "i"));
});

test("RPC checks expose bounded evidence and flag failed transactions", async () => {
  const payload = createPayload({
    projectTitle: "RPC evidence",
    projectDescription:
      "A project used to exercise bounded Solana evidence details.",
    repositoryUrl: "https://github.com/example/project",
    commit: "abcdef1234567890abcdef1234567890abcdef12",
    transactionSignature: encodeBase58(Buffer.alloc(64, 9)),
  });
  const fetchImpl = async (url) => {
    if (url.includes("api.github.com"))
      return {
        ok: true,
        status: 200,
        json: async () => ({ sha: "abcdef1234567890abcdef1234567890abcdef12" }),
      };
    return {
      ok: true,
      status: 200,
      json: async () => ({
        result: {
          slot: 42,
          blockTime: 1700000000,
          meta: { err: { InstructionError: [0, "Custom"] } },
        },
      }),
    };
  };
  const lookupImpl = async () => [{ address: "93.184.216.34", family: 4 }];
  const checks = await verifyNetwork(createEnvelope(payload), {
    fetchImpl,
    lookupImpl,
  });
  const solanaCheck = checks.find((check) => check.name === "solana_state");
  assert.equal(solanaCheck.status, "failed");
  assert.equal(solanaCheck.details.slot, 42);
  assert.equal(solanaCheck.details.blockTime, 1700000000);
  assert.match(solanaCheck.message, /execution error/i);
});

test("RPC transaction checks reject missing execution metadata", async () => {
  const payload = createPayload({
    projectTitle: "Incomplete RPC evidence",
    projectDescription:
      "A project used to reject transaction responses without execution metadata.",
    repositoryUrl: "https://github.com/example/project",
    commit: "abcdef1234567890abcdef1234567890abcdef12",
    transactionSignature: encodeBase58(Buffer.alloc(64, 10)),
  });
  const checks = await verifyNetwork(createEnvelope(payload), {
    lookupImpl: async () => [{ address: "93.184.216.34", family: 4 }],
    fetchImpl: async (url) =>
      url.includes("api.github.com")
        ? {
            ok: true,
            status: 200,
            json: async () => ({ sha: payload.repository.commit }),
          }
        : {
            ok: true,
            status: 200,
            json: async () => ({ result: { slot: 42, blockTime: 1700000000 } }),
          },
  });
  const solanaCheck = checks.find((check) => check.name === "solana_state");
  assert.equal(solanaCheck.status, "failed");
  assert.equal(solanaCheck.details.executionStatus, "unknown");
  assert.match(solanaCheck.message, /did not include execution status/i);
});

test("builder form creates a receipt from project metadata and renders it", async () => {
  const { startViewer } = await import("../src/viewer.mjs");
  const payload = createPayload({
    projectTitle: "Builder form",
    projectDescription:
      "A project used to exercise the builder-facing submission form.",
    repositoryUrl: "https://github.com/example/project",
    commit: "abcdef1234567890abcdef1234567890abcdef12",
  });
  const envelope = createEnvelope(payload);
  const viewer = await startViewer({ envelope, port: 0, network: false });
  try {
    const response = await fetch(`${viewer.url}`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        projectTitle: "Builder form",
        projectDescription: "A project used to exercise the builder-facing submission form.",
        repositoryUrl: "https://github.com/example/project",
        commit: "abcdef1234567890abcdef1234567890abcdef12",
        cluster: "devnet",
      }).toString(),
    });
    assert.equal(response.status, 200);
    const body = await response.text();
    assert.match(body, /Builder form/);
    assert.match(body, /Verification/);
  } finally {
    await viewer.close();
  }
});

test("reviewer upload accepts multipart JSON files", async () => {
  const { startViewer } = await import("../src/viewer.mjs");
  const payload = createPayload({
    projectTitle: "Multipart reviewer",
    projectDescription:
      "A project used to exercise reviewer uploads via a file input.",
    repositoryUrl: "https://github.com/example/project",
    commit: "abcdef1234567890abcdef1234567890abcdef12",
  });
  const envelope = createEnvelope(payload);
  const viewer = await startViewer({ envelope, port: 0, network: false });
  try {
    const form = new FormData();
    form.append("receipt", JSON.stringify(envelope));
    const response = await fetch(`${viewer.url}`, {
      method: "POST",
      body: form,
    });
    assert.equal(response.status, 200);
    assert.match(await response.text(), /Multipart reviewer/);
  } finally {
    await viewer.close();
  }
});

test("public verification API accepts a receipt payload and returns structured checks", async () => {
  const { startViewer } = await import("../src/viewer.mjs");
  const payload = createPayload({
    projectTitle: "Public verifier",
    projectDescription:
      "A project used to exercise the hosted verification API.",
    repositoryUrl: "https://github.com/example/project",
    commit: "abcdef1234567890abcdef1234567890abcdef12",
  });
  const envelope = createEnvelope(payload);
  const viewer = await startViewer({ envelope, port: 0, network: false });
  try {
    const response = await fetch(`${viewer.url}api/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(envelope),
    });
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.passed, true);
    assert.ok(Array.isArray(body.checks));
    assert.ok(body.checks.some((check) => check.name === "schema"));
  } finally {
    await viewer.close();
  }
});

test("viewer rejects oversized verification requests before parsing", async () => {
  const { startViewer } = await import("../src/viewer.mjs");
  const payload = createPayload({
    projectTitle: "Request limits",
    projectDescription: "A project used to exercise request body limits.",
    repositoryUrl: "https://github.com/example/project",
    commit: "abcdef1234567890abcdef1234567890abcdef12",
  });
  const viewer = await startViewer({
    envelope: createEnvelope(payload),
    port: 0,
    network: false,
  });
  try {
    const response = await fetch(`${viewer.url}api/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ receipt: "x".repeat(2 * 1024 * 1024) }),
    });
    assert.equal(response.status, 413);
    assert.match(await response.text(), /exceeds 2097152 bytes/i);
  } finally {
    await viewer.close();
  }
});

test("public reviewer page exposes a hosted verification form", async () => {
  const { startViewer } = await import("../src/viewer.mjs");
  const payload = createPayload({
    projectTitle: "Public review page",
    projectDescription:
      "A project used to exercise the hosted reviewer form.",
    repositoryUrl: "https://github.com/example/project",
    commit: "abcdef1234567890abcdef1234567890abcdef12",
  });
  const envelope = createEnvelope(payload);
  const viewer = await startViewer({ envelope, port: 0, network: false });
  try {
    const page = await fetch(`${viewer.url}review`);
    assert.equal(page.status, 200);
    const html = await page.text();
    assert.match(html, /Verify receipt/i);
    assert.match(html, /\/api\/verify/i);
    assert.match(html, /Verified/i);
    assert.match(html, /Warning/i);
    assert.match(html, /Failed/i);
    assert.match(html, /Not checked/i);
  } finally {
    await viewer.close();
  }
});

test("public reviewer page explains the core evidence flow", async () => {
  const { startViewer } = await import("../src/viewer.mjs");
  const payload = createPayload({
    projectTitle: "Receipt flow",
    projectDescription:
      "A project used to exercise the reviewer onboarding copy.",
    repositoryUrl: "https://github.com/example/project",
    commit: "abcdef1234567890abcdef1234567890abcdef12",
  });
  const envelope = createEnvelope(payload);
  const viewer = await startViewer({ envelope, port: 0, network: false });
  try {
    const page = await fetch(`${viewer.url}review`);
    assert.equal(page.status, 200);
    const html = await page.text();
    assert.match(html, /Git commit/i);
    assert.match(html, /On-chain evidence/i);
    assert.match(html, /Wallet attestation/i);
  } finally {
    await viewer.close();
  }
});

test("public reviewer page verifies a submitted receipt and renders the result", async () => {
  const { startViewer } = await import("../src/viewer.mjs");
  const payload = createPayload({
    projectTitle: "Submitted review",
    projectDescription:
      "A project used to exercise hosted verification rendering.",
    repositoryUrl: "https://github.com/example/project",
    commit: "abcdef1234567890abcdef1234567890abcdef12",
  });
  const envelope = createEnvelope(payload);
  const viewer = await startViewer({ envelope, port: 0, network: false });
  try {
    const response = await fetch(`${viewer.url}api/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(envelope),
    });
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.passed, true);
    assert.match(JSON.stringify(body), /schema/);
  } finally {
    await viewer.close();
  }
});

test("viewer allows explicit public hosts only with a safety gate", async () => {
  const { startViewer } = await import("../src/viewer.mjs");
  const payload = createPayload({
    projectTitle: "Public reviewer",
    projectDescription:
      "A project used to exercise an explicitly allowed public reviewer host.",
    repositoryUrl: "https://github.com/example/project",
    commit: "abcdef1234567890abcdef1234567890abcdef12",
  });
  const envelope = createEnvelope(payload);
  await assert.rejects(
    startViewer({ envelope, port: 0, host: "0.0.0.0", network: false }),
    /explicitly enabled/i,
  );
  const viewer = await startViewer({
    envelope,
    port: 0,
    host: "0.0.0.0",
    allowPublicHost: true,
    network: false,
  });
  try {
    assert.match(viewer.url, /^http:\/\/0\.0\.0\.0:/);
  } finally {
    await viewer.close();
  }
});

test("local viewer is loopback-only, read-only, and exposes HTML plus JSON", async () => {
  const { startViewer } = await import("../src/viewer.mjs");
  await assert.rejects(
    startViewer({
      envelope: { version: 1, payload: null, receiptHash: "bad" },
      port: 0,
    }),
    /Cannot serve invalid receipt/i,
  );
  const payload = createPayload({
    projectTitle: "Local viewer",
    projectDescription:
      "A project used to exercise the read-only local viewer.",
    repositoryUrl: "https://github.com/example/project",
    commit: "abcdef1234567890abcdef1234567890abcdef12",
  });
  const envelope = createEnvelope(payload);
  const viewer = await startViewer({ envelope, port: 0, network: false });
  try {
    assert.match(viewer.url, /^http:\/\/127\.0\.0\.1:/);
    const page = await fetch(viewer.url);
    assert.equal(page.status, 200);
    assert.match(
      page.headers.get("content-security-policy"),
      /default-src 'none'/,
    );
    assert.equal(page.headers.get("x-content-type-options"), "nosniff");
    assert.equal(page.headers.get("cache-control"), "no-store");
    assert.equal(
      page.headers.get("cross-origin-resource-policy"),
      "same-origin",
    );
    assert.equal(
      page.headers.get("permissions-policy"),
      "camera=(), microphone=(), geolocation=()",
    );
    assert.match(await page.text(), /Local viewer/);

    const health = await fetch(`${viewer.url}health`);
    assert.equal(health.status, 200);
    assert.equal(health.headers.get("content-type"), "application/json; charset=utf-8");
    assert.deepEqual(await health.json(), { status: "ok" });

    const receiptResponse = await fetch(`${viewer.url}api/receipt`);
    assert.equal(receiptResponse.status, 200);
    assert.equal(
      (await receiptResponse.json()).receiptHash,
      envelope.receiptHash,
    );

    const verificationResponse = await fetch(`${viewer.url}api/verification`);
    assert.equal(verificationResponse.status, 200);
    assert.equal((await verificationResponse.json()).passed, true);

    const mutation = await fetch(`${viewer.url}api/receipt`, {
      method: "POST",
      body: "{}",
    });
    assert.equal(mutation.status, 405);
    assert.equal(mutation.headers.get("allow"), "GET, HEAD");

    const posted = await fetch(`${viewer.url}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(envelope),
    });
    assert.equal(posted.status, 200);
    assert.match(await posted.text(), /Receipt upload/i);

    const missing = await fetch(`${viewer.url}missing`);
    assert.equal(missing.status, 404);
  } finally {
    await viewer.close();
  }
});

test("CLI bundle creates a complete reviewer artifact set", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ship-receipt-bundle-"));
  const receiptPath = join(dir, "input.json");
  const outputDir = join(dir, "reviewer-bundle");
  try {
    const payload = createPayload({
      projectTitle: "Reviewer bundle",
      projectDescription:
        "A project used to exercise reproducible reviewer artifacts.",
      repositoryUrl: "https://github.com/example/project",
      commit: "abcdef1234567890abcdef1234567890abcdef12",
    });
    const envelope = createEnvelope(payload);
    await writeFile(receiptPath, `${JSON.stringify(envelope, null, 2)}\n`);
    const command = await execFileAsync(
      process.execPath,
      ["src/cli.mjs", "bundle", receiptPath, "--out-dir", outputDir],
      { cwd: process.cwd() },
    );
    assert.match(command.stdout, /Created reviewer bundle/);

    const bundledReceipt = JSON.parse(
      await readFile(join(outputDir, "receipt.json"), "utf8"),
    );
    const bundledVerification = JSON.parse(
      await readFile(join(outputDir, "verification.json"), "utf8"),
    );
    const bundledHtml = await readFile(join(outputDir, "receipt.html"), "utf8");
    const manifest = JSON.parse(
      await readFile(join(outputDir, "manifest.json"), "utf8"),
    );
    assert.equal(bundledReceipt.receiptHash, envelope.receiptHash);
    assert.equal(bundledVerification.passed, true);
    assert.match(bundledHtml, /Reviewer bundle/);
    assert.deepEqual(manifest.files.map((file) => file.name).sort(), [
      "receipt.html",
      "receipt.json",
      "verification.json",
    ]);
    assert.equal(manifest.receiptHash, envelope.receiptHash);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("CLI audit verifies an intact reviewer bundle and identifies tampering", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ship-receipt-audit-"));
  const receiptPath = join(dir, "input.json");
  const outputDir = join(dir, "reviewer-bundle");
  try {
    const payload = createPayload({
      projectTitle: "Auditable bundle",
      projectDescription:
        "A reviewer bundle whose generated artifacts can be checked offline.",
      repositoryUrl: "https://github.com/example/project",
      commit: "abcdef1234567890abcdef1234567890abcdef12",
    });
    await writeFile(
      receiptPath,
      `${JSON.stringify(createEnvelope(payload), null, 2)}\n`,
    );
    await execFileAsync(
      process.execPath,
      ["src/cli.mjs", "bundle", receiptPath, "--out-dir", outputDir],
      { cwd: process.cwd() },
    );

    const cleanCommand = await execFileAsync(
      process.execPath,
      ["src/cli.mjs", "audit", outputDir, "--json"],
      { cwd: process.cwd() },
    );
    const cleanResult = JSON.parse(cleanCommand.stdout);
    assert.equal(cleanResult.passed, true);
    assert.equal(
      cleanResult.checks.find((check) => check.name === "receipt.html").status,
      "verified",
    );
    assert.equal(
      cleanResult.checks.find((check) => check.name === "receipt_envelope")
        .status,
      "verified",
    );
    assert.equal(
      cleanResult.checks.find((check) => check.name === "verification_record")
        .status,
      "verified",
    );

    await writeFile(
      join(outputDir, "receipt.html"),
      "<h1>altered after bundling</h1>\n",
    );
    let auditError;
    try {
      await execFileAsync(
        process.execPath,
        ["src/cli.mjs", "audit", outputDir, "--json"],
        { cwd: process.cwd() },
      );
    } catch (error) {
      auditError = error;
    }
    assert.ok(auditError, "tampered bundle should exit non-zero");
    const tamperedResult = JSON.parse(auditError.stdout);
    assert.equal(tamperedResult.passed, false);
    assert.equal(
      tamperedResult.checks.find((check) => check.name === "receipt.html")
        .status,
      "failed",
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("CLI audit rejects unexpected bundle files", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ship-receipt-extra-bundle-file-"));
  const receiptPath = join(dir, "input.json");
  const outputDir = join(dir, "reviewer-bundle");
  try {
    const payload = createPayload({
      projectTitle: "Strict bundle contents",
      projectDescription:
        "A reviewer bundle whose directory contents must match the documented contract.",
      repositoryUrl: "https://github.com/example/project",
      commit: "abcdef1234567890abcdef1234567890abcdef12",
    });
    await writeFile(
      receiptPath,
      `${JSON.stringify(createEnvelope(payload), null, 2)}\n`,
    );
    await execFileAsync(
      process.execPath,
      ["src/cli.mjs", "bundle", receiptPath, "--out-dir", outputDir],
      { cwd: process.cwd() },
    );
    await writeFile(
      join(outputDir, "unexpected.txt"),
      "not part of the bundle contract\n",
    );

    await assert.rejects(
      execFileAsync(
        process.execPath,
        ["src/cli.mjs", "audit", outputDir, "--json"],
        { cwd: process.cwd() },
      ),
      (error) => {
        const audit = JSON.parse(error.stdout);
        return (
          audit.checks.find((check) => check.name === "bundle_directory")
            ?.status === "failed"
        );
      },
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("CLI audit recomputes local verification semantics", async () => {
  const dir = await mkdtemp(
    join(tmpdir(), "ship-receipt-forged-verification-"),
  );
  const receiptPath = join(dir, "input.json");
  const outputDir = join(dir, "reviewer-bundle");
  try {
    const payload = createPayload({
      projectTitle: "Semantic bundle audit",
      projectDescription:
        "A reviewer bundle whose recorded local checks must match recomputation.",
      repositoryUrl: "https://github.com/example/project",
      commit: "abcdef1234567890abcdef1234567890abcdef12",
    });
    await writeFile(
      receiptPath,
      `${JSON.stringify(createEnvelope(payload), null, 2)}\n`,
    );
    await execFileAsync(
      process.execPath,
      ["src/cli.mjs", "bundle", receiptPath, "--out-dir", outputDir],
      { cwd: process.cwd() },
    );

    const verificationPath = join(outputDir, "verification.json");
    const manifestPath = join(outputDir, "manifest.json");
    const verification = JSON.parse(await readFile(verificationPath, "utf8"));
    verification.checks.find((check) => check.name === "receipt_hash").message =
      "Forged verification message";
    await writeFile(
      verificationPath,
      `${JSON.stringify(verification, null, 2)}\n`,
    );
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    manifest.files.find((file) => file.name === "verification.json").sha256 =
      createHash("sha256")
        .update(await readFile(verificationPath))
        .digest("hex");
    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);

    await assert.rejects(
      execFileAsync(
        process.execPath,
        ["src/cli.mjs", "audit", outputDir, "--json"],
        { cwd: process.cwd() },
      ),
      (error) => {
        const audit = JSON.parse(error.stdout);
        return (
          audit.checks.find((check) => check.name === "verification_semantics")
            ?.status === "failed"
        );
      },
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("CLI audit rejects malformed and partial verification records", async () => {
  const dir = await mkdtemp(
    join(tmpdir(), "ship-receipt-malformed-verification-"),
  );
  const receiptPath = join(dir, "input.json");
  const outputDir = join(dir, "reviewer-bundle");
  try {
    const payload = createPayload({
      projectTitle: "Strict verification record",
      projectDescription:
        "A reviewer bundle whose verification record must follow the exact contract.",
      repositoryUrl: "https://github.com/example/project",
      commit: "abcdef1234567890abcdef1234567890abcdef12",
    });
    await writeFile(
      receiptPath,
      `${JSON.stringify(createEnvelope(payload), null, 2)}\n`,
    );
    await execFileAsync(
      process.execPath,
      ["src/cli.mjs", "bundle", receiptPath, "--out-dir", outputDir],
      { cwd: process.cwd() },
    );

    const verificationPath = join(outputDir, "verification.json");
    const manifestPath = join(outputDir, "manifest.json");
    const verification = JSON.parse(await readFile(verificationPath, "utf8"));
    verification.checks.push({
      name: "github_commit",
      status: "verified",
      message: "Unsubstantiated partial network record",
    });
    verification.unexpected = true;
    await writeFile(
      verificationPath,
      `${JSON.stringify(verification, null, 2)}\n`,
    );
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    manifest.files.find((file) => file.name === "verification.json").sha256 =
      createHash("sha256")
        .update(await readFile(verificationPath))
        .digest("hex");
    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);

    await assert.rejects(
      execFileAsync(
        process.execPath,
        ["src/cli.mjs", "audit", outputDir, "--json"],
        { cwd: process.cwd() },
      ),
      (error) =>
        JSON.parse(error.stdout).checks.find(
          (item) => item.name === "verification_record",
        )?.status === "failed",
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("CLI audit rejects forged HTML even when its manifest hash is updated", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ship-receipt-forged-html-"));
  const receiptPath = join(dir, "input.json");
  const outputDir = join(dir, "reviewer-bundle");
  try {
    const payload = createPayload({
      projectTitle: "Semantic HTML audit",
      projectDescription:
        "A reviewer bundle whose HTML must remain derived from its receipt record.",
      repositoryUrl: "https://github.com/example/project",
      commit: "abcdef1234567890abcdef1234567890abcdef12",
    });
    await writeFile(
      receiptPath,
      `${JSON.stringify(createEnvelope(payload), null, 2)}\n`,
    );
    await execFileAsync(
      process.execPath,
      ["src/cli.mjs", "bundle", receiptPath, "--out-dir", outputDir],
      { cwd: process.cwd() },
    );

    const htmlPath = join(outputDir, "receipt.html");
    const manifestPath = join(outputDir, "manifest.json");
    await writeFile(htmlPath, "<h1>forged reviewer message</h1>\n");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    manifest.files.find((file) => file.name === "receipt.html").sha256 =
      createHash("sha256")
        .update(await readFile(htmlPath))
        .digest("hex");
    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);

    await assert.rejects(
      execFileAsync(
        process.execPath,
        ["src/cli.mjs", "audit", outputDir, "--json"],
        { cwd: process.cwd() },
      ),
      (error) => {
        const audit = JSON.parse(error.stdout);
        return (
          audit.checks.find((check) => check.name === "receipt_html_semantics")
            ?.status === "failed"
        );
      },
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("CLI audit reports each semantic invariant once", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ship-receipt-audit-checks-"));
  const receiptPath = join(dir, "input.json");
  const outputDir = join(dir, "reviewer-bundle");
  try {
    const payload = createPayload({
      projectTitle: "Unambiguous audit",
      projectDescription:
        "A reviewer bundle whose audit results must not contradict themselves.",
      repositoryUrl: "https://github.com/example/project",
      commit: "abcdef1234567890abcdef1234567890abcdef12",
    });
    await writeFile(
      receiptPath,
      `${JSON.stringify(createEnvelope(payload), null, 2)}\n`,
    );
    await execFileAsync(
      process.execPath,
      ["src/cli.mjs", "bundle", receiptPath, "--out-dir", outputDir],
      { cwd: process.cwd() },
    );
    await rm(join(outputDir, "receipt.html"));

    let auditError;
    try {
      await execFileAsync(
        process.execPath,
        ["src/cli.mjs", "audit", outputDir, "--json"],
        { cwd: process.cwd() },
      );
    } catch (error) {
      auditError = error;
    }
    assert.ok(auditError);
    const audit = JSON.parse(auditError.stdout);
    const names = audit.checks.map((check) => check.name);
    assert.equal(new Set(names).size, names.length);
    assert.equal(
      audit.checks.find((check) => check.name === "receipt_envelope").status,
      "verified",
    );
    assert.equal(
      audit.checks.find((check) => check.name === "receipt_html_semantics")
        .status,
      "failed",
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("CLI bundle exits non-zero when its receipt verification fails", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ship-receipt-failed-bundle-"));
  const receiptPath = join(dir, "input.json");
  const outputDir = join(dir, "reviewer-bundle");
  try {
    const payload = createPayload({
      projectTitle: "Failed evidence",
      projectDescription:
        "A deliberately altered receipt used to enforce failed bundle exit status.",
      repositoryUrl: "https://github.com/example/project",
      commit: "abcdef1234567890abcdef1234567890abcdef12",
    });
    const envelope = createEnvelope(payload);
    envelope.payload.projectDescription =
      "Altered after hashing so local verification must fail.";
    await writeFile(receiptPath, `${JSON.stringify(envelope, null, 2)}\n`);

    let bundleError;
    try {
      await execFileAsync(
        process.execPath,
        ["src/cli.mjs", "bundle", receiptPath, "--out-dir", outputDir],
        { cwd: process.cwd() },
      );
    } catch (error) {
      bundleError = error;
    }
    assert.ok(bundleError, "failed receipt should make bundle exit non-zero");
    const verification = JSON.parse(
      await readFile(join(outputDir, "verification.json"), "utf8"),
    );
    assert.equal(verification.passed, false);

    let auditError;
    try {
      await execFileAsync(
        process.execPath,
        ["src/cli.mjs", "audit", outputDir, "--json"],
        { cwd: process.cwd() },
      );
    } catch (error) {
      auditError = error;
    }
    assert.ok(
      auditError,
      "bundle containing failed verification should fail audit",
    );
    const audit = JSON.parse(auditError.stdout);
    assert.equal(
      audit.checks.find((check) => check.name === "verification_record").status,
      "failed",
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("CLI audit handles a non-object manifest as a structured failure", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ship-receipt-null-manifest-"));
  const receiptPath = join(dir, "input.json");
  const outputDir = join(dir, "reviewer-bundle");
  try {
    const payload = createPayload({
      projectTitle: "Malformed manifest",
      projectDescription:
        "A valid receipt whose bundle manifest is replaced with a non-object JSON value.",
      repositoryUrl: "https://github.com/example/project",
      commit: "abcdef1234567890abcdef1234567890abcdef12",
    });
    await writeFile(
      receiptPath,
      `${JSON.stringify(createEnvelope(payload), null, 2)}\n`,
    );
    await execFileAsync(
      process.execPath,
      ["src/cli.mjs", "bundle", receiptPath, "--out-dir", outputDir],
      { cwd: process.cwd() },
    );
    await writeFile(join(outputDir, "manifest.json"), "null\n");

    let auditError;
    try {
      await execFileAsync(
        process.execPath,
        ["src/cli.mjs", "audit", outputDir, "--json"],
        { cwd: process.cwd() },
      );
    } catch (error) {
      auditError = error;
    }
    assert.ok(auditError, "invalid manifest should exit non-zero");
    const audit = JSON.parse(auditError.stdout);
    assert.equal(audit.passed, false);
    assert.equal(
      audit.checks.find((check) => check.name === "manifest").status,
      "failed",
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("CLI bundle refuses to overwrite an existing reviewer bundle", async () => {
  const dir = await mkdtemp(join(tmpdir(), "ship-receipt-no-overwrite-"));
  const receiptPath = join(dir, "input.json");
  const outputDir = join(dir, "reviewer-bundle");
  try {
    const payload = createPayload({
      projectTitle: "Immutable reviewer evidence",
      projectDescription:
        "A reviewer bundle should never be silently replaced by a later command.",
      repositoryUrl: "https://github.com/example/project",
      commit: "abcdef1234567890abcdef1234567890abcdef12",
    });
    await writeFile(
      receiptPath,
      `${JSON.stringify(createEnvelope(payload), null, 2)}\n`,
    );
    await execFileAsync(
      process.execPath,
      ["src/cli.mjs", "bundle", receiptPath, "--out-dir", outputDir],
      { cwd: process.cwd() },
    );
    const originalManifest = await readFile(
      join(outputDir, "manifest.json"),
      "utf8",
    );

    await assert.rejects(
      execFileAsync(
        process.execPath,
        ["src/cli.mjs", "bundle", receiptPath, "--out-dir", outputDir],
        { cwd: process.cwd() },
      ),
      (error) => /must not already exist/i.test(error.stderr),
    );
    assert.equal(
      await readFile(join(outputDir, "manifest.json"), "utf8"),
      originalManifest,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("guided receipt skill documents the safe evidence workflow", async () => {
  const skillPath = join(
    process.cwd(),
    "skills",
    "solana-ship-receipt",
    "SKILL.md",
  );
  const interfacePath = join(
    process.cwd(),
    "skills",
    "solana-ship-receipt",
    "agents",
    "openai.yaml",
  );
  const skill = await readFile(skillPath, "utf8");
  const ui = await readFile(interfacePath, "utf8");
  assert.match(skill, /^---\nname: solana-ship-receipt\ndescription: .+\n---/);
  assert.match(skill, /exact 40-character commit/i);
  assert.match(skill, /local verification before network verification/i);
  assert.match(skill, /bundle .* audit/i);
  assert.match(skill, /never request or expose private keys/i);
  assert.doesNotMatch(skill, /git push|git commit/i);
  assert.match(ui, /display_name:/);
  assert.match(ui, /default_prompt:/);
});

test("ships three reproducible receipts from public Solana repositories", async () => {
  const fixtureDir = join(process.cwd(), "fixtures", "public-projects");
  const names = (await readdir(fixtureDir))
    .filter((name) => name.endsWith(".json"))
    .sort();
  assert.equal(names.length, 3);
  const repositories = new Set();
  for (const name of names) {
    const envelope = JSON.parse(await readFile(join(fixtureDir, name), "utf8"));
    const result = await verifyEnvelope(envelope);
    assert.equal(result.passed, true, `${name} should verify locally`);
    assert.match(
      envelope.payload.repository.url,
      /^https:\/\/github\.com\/[^/]+\/[^/]+$/,
    );
    assert.match(envelope.payload.repository.commit, /^[0-9a-f]{40}$/);
    repositories.add(envelope.payload.repository.url);
  }
  assert.equal(repositories.size, 3);
});
