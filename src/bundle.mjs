import { createHash } from "node:crypto";
import {
  lstat,
  mkdir,
  readFile,
  readdir,
  rm,
  rmdir,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { canonicalJson, renderHtml, verifyEnvelope } from "./receipt.mjs";

const BUNDLE_FILES = ["receipt.json", "verification.json", "receipt.html"];
const BUNDLE_DIRECTORY_FILES = [...BUNDLE_FILES, "manifest.json"];
const LOCAL_CHECK_ORDER = ["version", "schema", "receipt_hash", "attestation"];
const NETWORK_CHECK_ORDER = ["github_commit", "solana_state", "demo_url"];
const LOCAL_CHECK_NAMES = new Set(LOCAL_CHECK_ORDER);
const CHECK_NAMES = new Set([...LOCAL_CHECK_ORDER, ...NETWORK_CHECK_ORDER]);
const CHECK_STATUSES = new Set([
  "verified",
  "warning",
  "failed",
  "not_checked",
]);
const MANIFEST_KEYS = new Set([
  "version",
  "receiptHash",
  "verifiedAt",
  "files",
]);
const MANIFEST_FILE_KEYS = new Set(["name", "sha256"]);
const VERIFICATION_KEYS = new Set(["passed", "verifiedAt", "checks"]);
const VERIFICATION_CHECK_KEYS = new Set([
  "name",
  "status",
  "message",
  "details",
]);
const MAX_BUNDLE_FILE_BYTES = 2 * 1024 * 1024;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;

async function readJson(path) {
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.size > MAX_BUNDLE_FILE_BYTES)
    throw new Error(
      `${path} is not a readable bundle file within the size limit`,
    );
  return JSON.parse(await readFile(path, "utf8"));
}

async function writeJson(path, value) {
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, {
    encoding: "utf8",
    flag: "wx",
  });
}

async function fileHash(path) {
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.size > MAX_BUNDLE_FILE_BYTES)
    throw new Error(
      `${path} is not a readable bundle file within the size limit`,
    );
  return createHash("sha256")
    .update(await readFile(path))
    .digest("hex");
}

function check(name, status, message, details) {
  return { name, status, message, ...(details ? { details } : {}) };
}

function isIsoTimestamp(value) {
  if (typeof value !== "string") return false;
  const timestamp = Date.parse(value);
  return (
    Number.isFinite(timestamp) && new Date(timestamp).toISOString() === value
  );
}

export async function createReviewerBundle({
  envelope,
  outDir,
  network = false,
}) {
  const verification = await verifyEnvelope(envelope, { network });
  const schemaCheck = verification.checks.find(
    (item) => item.name === "schema",
  );
  if (schemaCheck?.status === "failed")
    throw new Error(`Cannot bundle invalid receipt: ${schemaCheck.message}`);
  const generatedPaths = [
    join(outDir, "receipt.json"),
    join(outDir, "verification.json"),
    join(outDir, "receipt.html"),
    join(outDir, "manifest.json"),
  ];
  try {
    await mkdir(outDir);
  } catch (error) {
    if (error?.code === "EEXIST")
      throw new Error(
        `Bundle output directory must not already exist: ${outDir}`,
      );
    throw error;
  }

  try {
    const paths = {
      "receipt.json": join(outDir, "receipt.json"),
      "verification.json": join(outDir, "verification.json"),
      "receipt.html": join(outDir, "receipt.html"),
    };
    await writeJson(paths["receipt.json"], envelope);
    await writeJson(paths["verification.json"], verification);
    await writeFile(paths["receipt.html"], renderHtml(envelope, verification), {
      encoding: "utf8",
      flag: "wx",
    });

    const files = [];
    for (const name of BUNDLE_FILES)
      files.push({ name, sha256: await fileHash(paths[name]) });
    const manifest = {
      version: 1,
      receiptHash: envelope.receiptHash,
      verifiedAt: verification.verifiedAt,
      files,
    };
    await writeJson(join(outDir, "manifest.json"), manifest);
    return { manifest, verification };
  } catch (error) {
    for (const path of generatedPaths)
      await rm(path, { force: true }).catch(() => {});
    await rmdir(outDir).catch(() => {});
    throw error;
  }
}

export async function auditReviewerBundle(outDir) {
  const checks = [];
  let manifest;
  try {
    manifest = await readJson(join(outDir, "manifest.json"));
  } catch (error) {
    checks.push(
      check(
        "manifest",
        "failed",
        `Cannot read manifest.json: ${error.message}`,
      ),
    );
    return { passed: false, auditedAt: new Date().toISOString(), checks };
  }

  const manifestObject =
    manifest && typeof manifest === "object" && !Array.isArray(manifest);
  const manifestReceiptHash = manifestObject ? manifest.receiptHash : undefined;
  const manifestVerifiedAt = manifestObject ? manifest.verifiedAt : undefined;
  const manifestShapeValid =
    manifestObject &&
    Object.keys(manifest).every((key) => MANIFEST_KEYS.has(key)) &&
    manifest.version === 1 &&
    SHA256_PATTERN.test(manifest?.receiptHash ?? "") &&
    isIsoTimestamp(manifest?.verifiedAt) &&
    Array.isArray(manifest?.files);
  checks.push(
    check(
      "manifest",
      manifestShapeValid ? "verified" : "failed",
      manifestShapeValid
        ? "Manifest structure is supported"
        : "Manifest structure is invalid or unsupported",
    ),
  );

  try {
    const directoryEntries = await readdir(outDir, { withFileTypes: true });
    const actualNames = directoryEntries.map((entry) => entry.name);
    const unexpected = actualNames.filter(
      (name) => !BUNDLE_DIRECTORY_FILES.includes(name),
    );
    const missing = BUNDLE_DIRECTORY_FILES.filter(
      (name) => !actualNames.includes(name),
    );
    const nonFiles = directoryEntries
      .filter(
        (entry) =>
          BUNDLE_DIRECTORY_FILES.includes(entry.name) && !entry.isFile(),
      )
      .map((entry) => entry.name);
    const directoryIsValid =
      unexpected.length === 0 && missing.length === 0 && nonFiles.length === 0;
    checks.push(
      check(
        "bundle_directory",
        directoryIsValid ? "verified" : "failed",
        directoryIsValid
          ? "Bundle directory contains exactly the documented artifacts"
          : "Bundle directory contains unexpected, missing, or non-file artifacts",
        { unexpected, missing, nonFiles },
      ),
    );
  } catch (error) {
    checks.push(
      check(
        "bundle_directory",
        "failed",
        `Cannot inspect bundle directory: ${error.message}`,
      ),
    );
  }

  const entries = manifestShapeValid ? manifest.files : [];
  const names = entries.map((entry) => entry?.name);
  const exactFileSet =
    entries.length === BUNDLE_FILES.length &&
    BUNDLE_FILES.every(
      (name) => names.filter((candidate) => candidate === name).length === 1,
    ) &&
    entries.every(
      (entry) =>
        entry &&
        typeof entry === "object" &&
        !Array.isArray(entry) &&
        Object.keys(entry).every((key) => MANIFEST_FILE_KEYS.has(key)) &&
        BUNDLE_FILES.includes(entry.name) &&
        SHA256_PATTERN.test(entry.sha256 ?? ""),
    );
  checks.push(
    check(
      "manifest_files",
      exactFileSet ? "verified" : "failed",
      exactFileSet
        ? "Manifest contains the expected artifact allowlist"
        : "Manifest file entries are missing, duplicated, unexpected, or malformed",
    ),
  );

  for (const name of BUNDLE_FILES) {
    const entry = exactFileSet
      ? entries.find((candidate) => candidate.name === name)
      : undefined;
    if (!entry) {
      checks.push(check(name, "failed", `${name} has no valid manifest entry`));
      continue;
    }
    try {
      const actual = await fileHash(join(outDir, name));
      const matches = actual === entry.sha256;
      checks.push(
        check(
          name,
          matches ? "verified" : "failed",
          matches
            ? `${name} matches its manifest hash`
            : `${name} does not match its manifest hash`,
          { expectedSha256: entry.sha256, actualSha256: actual },
        ),
      );
    } catch (error) {
      checks.push(
        check(name, "failed", `Cannot read ${name}: ${error.message}`),
      );
    }
  }

  let recordedVerification;
  try {
    const verification = await readJson(join(outDir, "verification.json"));
    recordedVerification = verification;
    const checkNames = Array.isArray(verification?.checks)
      ? verification.checks.map((item) => item?.name)
      : [];
    const hasExpectedCheckSequence = [
      LOCAL_CHECK_ORDER,
      [...LOCAL_CHECK_ORDER, ...NETWORK_CHECK_ORDER],
    ].some(
      (expected) =>
        expected.length === checkNames.length &&
        expected.every((name, index) => checkNames[index] === name),
    );
    const verificationShapeIsValid =
      verification &&
      typeof verification === "object" &&
      !Array.isArray(verification) &&
      Object.keys(verification).length === VERIFICATION_KEYS.size &&
      Object.keys(verification).every((key) => VERIFICATION_KEYS.has(key));
    const checksHaveValidShape =
      verificationShapeIsValid &&
      Array.isArray(verification.checks) &&
      hasExpectedCheckSequence &&
      verification.checks.every(
        (item) =>
          item &&
          typeof item === "object" &&
          !Array.isArray(item) &&
          Object.keys(item).every((key) => VERIFICATION_CHECK_KEYS.has(key)) &&
          typeof item.name === "string" &&
          CHECK_NAMES.has(item.name) &&
          CHECK_STATUSES.has(item.status) &&
          typeof item.message === "string" &&
          item.message.length > 0 &&
          (!Object.hasOwn(item, "details") ||
            (item.details &&
              typeof item.details === "object" &&
              !Array.isArray(item.details))),
      ) &&
      new Set(checkNames).size === checkNames.length;
    const passedIsConsistent =
      checksHaveValidShape &&
      verification.passed ===
        verification.checks.every((item) => item.status !== "failed");
    const valid =
      verification?.passed === true &&
      verification?.verifiedAt === manifestVerifiedAt &&
      isIsoTimestamp(verification?.verifiedAt) &&
      checksHaveValidShape &&
      passedIsConsistent;
    checks.push(
      check(
        "verification_record",
        valid ? "verified" : "failed",
        valid
          ? "Verification record passed and matches the manifest timestamp"
          : "Verification record is malformed, failed, or does not match the manifest timestamp",
        {
          recordedPassed: verification?.passed,
          verifiedAt: verification?.verifiedAt,
          manifestVerifiedAt,
        },
      ),
    );
  } catch (error) {
    checks.push(
      check(
        "verification_record",
        "failed",
        `Cannot validate verification.json: ${error.message}`,
      ),
    );
  }

  let receipt;
  let localVerification;
  try {
    receipt = await readJson(join(outDir, "receipt.json"));
    localVerification = await verifyEnvelope(receipt);
    const matchesManifest = receipt.receiptHash === manifestReceiptHash;
    const valid = localVerification.passed && matchesManifest;
    checks.push(
      check(
        "receipt_envelope",
        valid ? "verified" : "failed",
        valid
          ? "Receipt envelope is valid and matches the manifest"
          : "Receipt envelope is invalid or does not match the manifest",
        { receiptHash: receipt.receiptHash, manifestReceiptHash },
      ),
    );
  } catch (error) {
    checks.push(
      check(
        "receipt_envelope",
        "failed",
        `Cannot verify receipt envelope: ${error.message}`,
      ),
    );
  }

  if (localVerification) {
    const recordedLocalChecks =
      recordedVerification?.checks?.filter((item) =>
        LOCAL_CHECK_NAMES.has(item?.name),
      ) ?? [];
    const expectedLocalChecks = localVerification.checks.filter((item) =>
      LOCAL_CHECK_NAMES.has(item.name),
    );
    const localChecksMatch =
      canonicalJson(recordedLocalChecks) === canonicalJson(expectedLocalChecks);
    checks.push(
      check(
        "verification_semantics",
        localChecksMatch ? "verified" : "failed",
        localChecksMatch
          ? "Recorded local verification checks match recomputation"
          : "Recorded local verification checks do not match recomputation",
        { recordedLocalChecks, expectedLocalChecks },
      ),
    );
  } else {
    checks.push(
      check(
        "verification_semantics",
        "failed",
        "Cannot recompute verification semantics without a valid receipt",
      ),
    );
  }

  try {
    if (!receipt || !recordedVerification)
      throw new Error("Receipt or verification record is unavailable");
    const expectedHtml = renderHtml(receipt, recordedVerification);
    const htmlPath = join(outDir, "receipt.html");
    const htmlMetadata = await lstat(htmlPath);
    if (!htmlMetadata.isFile() || htmlMetadata.size > MAX_BUNDLE_FILE_BYTES)
      throw new Error(
        "receipt.html is not a readable bundle file within the size limit",
      );
    const actualHtml = await readFile(htmlPath, "utf8");
    const htmlMatches = actualHtml === expectedHtml;
    checks.push(
      check(
        "receipt_html_semantics",
        htmlMatches ? "verified" : "failed",
        htmlMatches
          ? "Rendered HTML matches the receipt and verification record"
          : "Rendered HTML does not match the receipt and verification record",
      ),
    );
  } catch (error) {
    checks.push(
      check(
        "receipt_html_semantics",
        "failed",
        `Cannot validate rendered HTML semantics: ${error.message}`,
      ),
    );
  }

  const passed = checks.every((item) => item.status === "verified");
  return {
    passed,
    auditedAt: new Date().toISOString(),
    ...(manifestReceiptHash ? { receiptHash: manifestReceiptHash } : {}),
    checks,
  };
}
