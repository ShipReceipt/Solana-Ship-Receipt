#!/usr/bin/env node
import { readFile, stat, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import {
  createEnvelope,
  createPayload,
  renderHtml,
  signEnvelope,
  verifyEnvelope,
} from "./receipt.mjs";
import { startViewer } from "./viewer.mjs";
import { auditReviewerBundle, createReviewerBundle } from "./bundle.mjs";

const packageMetadata = JSON.parse(
  await readFile(new URL("../package.json", import.meta.url), "utf8"),
);
const VERSION = packageMetadata.version;
const MAX_RECEIPT_FILE_BYTES = 2 * 1024 * 1024;

function usage() {
  console.log(`Solana Ship Receipt v${VERSION}

First run (from this repository):
  node src/cli.mjs sample --out first.receipt.json
  node src/cli.mjs verify first.receipt.json
  node src/cli.mjs render first.receipt.json --out first.receipt.html

Commands:
  create   --title T --description D --repo URL --commit SHA [options]
  sign     RECEIPT.json --keypair PATH [--out PATH]  (default: RECEIPT.signed.json)
  verify   RECEIPT.json [--network] [--json]
  render   RECEIPT.json [--out PATH] [--network]
  serve    RECEIPT.json [--port PORT] [--network] [--host HOST] [--public]
  bundle   RECEIPT.json --out-dir DIR [--network]
  audit    BUNDLE_DIR [--json]
  sample   [--out PATH]

Create options:
  --cluster mainnet|devnet|testnet   (default: devnet)
  --rpc URL --tx SIGNATURE --program PROGRAM_ID --memo HASH --verified-build-url URL --demo URL --keypair PATH --out PATH

Serve options:
  --host 127.0.0.1|0.0.0.0   (default: 127.0.0.1)
  --public                     (explicit opt-in for non-loopback hosting; not enabled by default)

Notes:
  --commit requires the full 40-character Git SHA (try: git rev-parse HEAD)
  Generated artifacts are write-once; choose a new output path for each revision
  Installed package users can replace "node src/cli.mjs" with "ship-receipt"

Guide:
  https://github.com/ShipReceipt/Solana-Ship-Receipt/blob/main/docs/GETTING-STARTED.md
`);
}

const COMMAND_OPTIONS = {
  create: new Set([
    "title",
    "description",
    "repo",
    "commit",
    "cluster",
    "rpc",
    "tx",
    "program",
    "memo",
    "verified-build-url",
    "demo",
    "out",
    "keypair",
  ]),
  sign: new Set(["keypair", "out"]),
  verify: new Set(["network", "json"]),
  render: new Set(["out", "network"]),
  serve: new Set(["port", "network", "host", "public"]),
  bundle: new Set(["out-dir", "network"]),
  audit: new Set(["json"]),
  sample: new Set(["out"]),
};

const BOOLEAN_OPTIONS = new Set(["network", "json", "public"]);
const POSITIONAL_COUNTS = {
  create: 0,
  sign: 1,
  verify: 1,
  render: 1,
  serve: 1,
  bundle: 1,
  audit: 1,
  sample: 0,
};

function argsToObject(args, command) {
  const result = { _: [] };
  const allowedOptions = COMMAND_OPTIONS[command];
  if (!allowedOptions) throw new Error(`Unknown command ${command}`);
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (!arg.startsWith("--")) {
      result._.push(arg);
      continue;
    }
    const key = arg.slice(2);
    if (!allowedOptions.has(key))
      throw new Error(`Unknown option --${key} for ${command}`);
    if (Object.hasOwn(result, key))
      throw new Error(`Duplicate option --${key} for ${command}`);
    if (BOOLEAN_OPTIONS.has(key)) {
      result[key] = true;
      continue;
    }
    const value = args[i + 1];
    if (!value || value.startsWith("--"))
      throw new Error(`Missing value for --${key}`);
    result[key] = value;
    i += 1;
  }
  if (result._.length > POSITIONAL_COUNTS[command]) {
    throw new Error(
      `Unexpected positional argument for ${command}: ${result._[POSITIONAL_COUNTS[command]]}`,
    );
  }
  return result;
}

async function readJson(path) {
  const metadata = await stat(path);
  if (!metadata.isFile() || metadata.size > MAX_RECEIPT_FILE_BYTES)
    throw new Error(
      `Input must be a JSON file no larger than ${MAX_RECEIPT_FILE_BYTES} bytes: ${path}`,
    );
  return JSON.parse(await readFile(path, "utf8"));
}
async function writeExclusive(path, content) {
  try {
    await writeFile(path, content, { encoding: "utf8", flag: "wx" });
  } catch (error) {
    if (error?.code === "EEXIST")
      throw new Error(`Refusing to replace existing output: ${path}`);
    throw error;
  }
}

async function writeJsonExclusive(path, value) {
  await writeExclusive(path, `${JSON.stringify(value, null, 2)}\n`);
}

function siblingOutputPath(input, suffix) {
  return input.toLowerCase().endsWith(".json")
    ? `${input.slice(0, -5)}${suffix}`
    : `${input}${suffix}`;
}

const [command, ...rawArgs] = process.argv.slice(2);
if (
  !command ||
  command === "help" ||
  command === "--help" ||
  command === "-h"
) {
  usage();
  process.exit(0);
}
if (["--version", "-v", "version"].includes(command)) {
  console.log(`solana-ship-receipt v${VERSION}`);
  process.exit(0);
}

try {
  const args = argsToObject(rawArgs, command);
  if (command === "create") {
    const payload = createPayload({
      projectTitle: args.title,
      projectDescription: args.description,
      repositoryUrl: args.repo,
      commit: args.commit,
      cluster: args.cluster,
      rpcUrl: args.rpc,
      transactionSignature: args.tx,
      programId: args.program,
      memo: args.memo,
      verifiedBuildUrl: args["verified-build-url"],
      demoUrl: args.demo,
    });
    let envelope = createEnvelope(payload);
    if (args.keypair) envelope = await signEnvelope(envelope, args.keypair);
    const out = args.out || "ship-receipt.json";
    await writeJsonExclusive(out, envelope);
    console.log(`Created ${out}\nReceipt hash: ${envelope.receiptHash}`);
  } else if (command === "sign") {
    const input = args._[0];
    if (!input || !args.keypair)
      throw new Error("sign requires RECEIPT.json and --keypair PATH");
    const envelope = await signEnvelope(await readJson(input), args.keypair);
    const out = args.out || siblingOutputPath(input, ".signed.json");
    if (resolve(out) === resolve(input))
      throw new Error(
        "Refusing to overwrite the source receipt; choose a different --out path",
      );
    await writeJsonExclusive(out, envelope);
    console.log(
      `Signed ${out}\nSource preserved: ${input}\nWallet: ${envelope.attestation.publicKey}`,
    );
  } else if (command === "verify") {
    const input = args._[0];
    if (!input) throw new Error("verify requires RECEIPT.json");
    const result = await verifyEnvelope(await readJson(input), {
      network: args.network,
    });
    if (args.json) console.log(JSON.stringify(result, null, 2));
    else
      for (const check of result.checks)
        console.log(
          `${check.status.padEnd(11)} ${check.name}: ${check.message}`,
        );
    process.exitCode = result.passed ? 0 : 1;
  } else if (command === "render") {
    const input = args._[0];
    if (!input) throw new Error("render requires RECEIPT.json");
    const envelope = await readJson(input);
    const result = await verifyEnvelope(envelope, { network: args.network });
    const schemaCheck = result.checks.find((check) => check.name === "schema");
    if (schemaCheck?.status === "failed")
      throw new Error(`Cannot render invalid receipt: ${schemaCheck.message}`);
    const out = args.out || siblingOutputPath(input, ".html");
    if (resolve(out) === resolve(input))
      throw new Error(
        "Refusing to overwrite the source receipt; choose a different --out path",
      );
    await writeExclusive(out, renderHtml(envelope, result));
    console.log(`Rendered ${out}`);
  } else if (command === "serve") {
    const input = args._[0];
    if (!input) throw new Error("serve requires RECEIPT.json");
    const port = args.port === undefined ? 8787 : Number(args.port);
    if (!Number.isInteger(port) || port < 0 || port > 65535)
      throw new Error("--port must be an integer from 0 to 65535");
    const host = args.host || "127.0.0.1";
    const viewer = await startViewer({
      envelope: await readJson(input),
      port,
      host,
      network: args.network,
      allowPublicHost: Boolean(args.public),
    });
    console.log(`Serving ${input} at ${viewer.url}`);
    await new Promise(() => {});
  } else if (command === "bundle") {
    const input = args._[0];
    if (!input || !args["out-dir"])
      throw new Error("bundle requires RECEIPT.json and --out-dir DIR");
    const outDir = args["out-dir"];
    const envelope = await readJson(input);
    const { verification } = await createReviewerBundle({
      envelope,
      outDir,
      network: args.network,
    });
    console.log(`Created reviewer bundle in ${outDir}`);
    process.exitCode = verification.passed ? 0 : 1;
  } else if (command === "audit") {
    const input = args._[0];
    if (!input) throw new Error("audit requires BUNDLE_DIR");
    const result = await auditReviewerBundle(input);
    if (args.json) console.log(JSON.stringify(result, null, 2));
    else
      for (const item of result.checks)
        console.log(`${item.status.padEnd(11)} ${item.name}: ${item.message}`);
    process.exitCode = result.passed ? 0 : 1;
  } else if (command === "sample") {
    const out = args.out || "sample.receipt.json";
    const payload = createPayload({
      projectTitle: "Metaplex Token Metadata",
      projectDescription:
        "A public Metaplex Token Metadata fixture pinned to an exact repository revision.",
      repositoryUrl: "https://github.com/metaplex-foundation/mpl-token-metadata",
      commit: "349e061053c6fc5b6b815e03e896e4db57012893",
      cluster: "devnet",
      createdAt: "2026-08-23T00:00:00.000Z",
      receiptId: "00000000-0000-4000-8000-000000000002",
    });
    await writeJsonExclusive(out, createEnvelope(payload));
    console.log(`Created ${out}`);
  } else {
    usage();
    process.exitCode = 1;
  }
} catch (error) {
  console.error(`Error: ${error.message}`);
  process.exitCode = 1;
}
