import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomUUID,
  sign,
  verify,
} from "node:crypto";
import { lookup as lookupHost } from "node:dns/promises";
import { isIP } from "node:net";
import { readFile, stat } from "node:fs/promises";
import { decodeBase58, encodeBase58 } from "./base58.mjs";

const DEFAULT_RPC = {
  mainnet: "https://api.mainnet-beta.solana.com",
  devnet: "https://api.devnet.solana.com",
  testnet: "https://api.testnet.solana.com",
};

const PRIVATE_KEY_PREFIX = Buffer.from(
  "302e020100300506032b657004220420",
  "hex",
);
const PUBLIC_KEY_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const ATTESTATION_CONTEXT = "solana-ship-receipt/v1";
const ATTESTATION_PREFIX = Buffer.from(`${ATTESTATION_CONTEXT}\n`, "utf8");
const PAYLOAD_KEYS = new Set([
  "projectTitle",
  "projectDescription",
  "repository",
  "solana",
  "demoUrl",
  "verifiedBuildUrl",
  "createdAt",
  "receiptId",
]);
const REPOSITORY_KEYS = new Set(["url", "commit"]);
const SOLANA_KEYS = new Set([
  "cluster",
  "rpcUrl",
  "transactionSignature",
  "programId",
  "memo",
]);
const ENVELOPE_KEYS = new Set([
  "version",
  "payload",
  "receiptHash",
  "attestation",
]);
const ATTESTATION_KEYS = new Set([
  "publicKey",
  "signature",
  "algorithm",
  "context",
]);
const RFC3339_PATTERN =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(Z|([+-])(\d{2}):(\d{2}))$/;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const GITHUB_SEGMENT_PATTERN = /^[A-Za-z0-9_.-]+$/;
const MAX_TITLE_LENGTH = 120;
const MAX_DESCRIPTION_LENGTH = 1000;
const MAX_URL_LENGTH = 2048;
const MAX_RESPONSE_BYTES = 256 * 1024;
const MAX_KEYPAIR_FILE_BYTES = 4 * 1024;

function withoutEmptyValues(value) {
  if (Array.isArray(value)) return value.map(withoutEmptyValues);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .filter(
          ([, item]) => item !== undefined && item !== null && item !== "",
        )
        .map(([key, item]) => [key, withoutEmptyValues(item)]),
    );
  }
  return value;
}

function sortKeys(value) {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, sortKeys(value[key])]),
    );
  }
  return value;
}

export function canonicalJson(value) {
  return JSON.stringify(sortKeys(value));
}

export function canonicalBytes(value) {
  return Buffer.from(canonicalJson(value), "utf8");
}

export function sha256(value) {
  return createHash("sha256").update(canonicalBytes(value)).digest("hex");
}

function hashablePayload(payload) {
  if (!payload || typeof payload !== "object") return payload;
  if (!Object.hasOwn(payload, "solana") || !payload.solana || typeof payload.solana !== "object")
    return payload;
  return {
    ...payload,
    solana: { ...payload.solana, memo: undefined },
  };
}

function attestationBytes(payload) {
  return Buffer.concat([ATTESTATION_PREFIX, canonicalBytes(payload)]);
}

function requireHttpUrl(value, label) {
  if (typeof value !== "string" || value.length === 0)
    throw new Error(`${label} must be a URL string`);
  if (value.length > MAX_URL_LENGTH)
    throw new Error(`${label} must not exceed ${MAX_URL_LENGTH} characters`);
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${label} must be a valid URL`);
  }
  if (!/^https?:$/.test(parsed.protocol))
    throw new Error(`${label} must use http or https`);
  if (parsed.username || parsed.password)
    throw new Error(`${label} cannot contain credentials`);
  const hostname = parsed.hostname
    .toLowerCase()
    .replace(/^\[|\]$/g, "")
    .replace(/\.$/, "");
  if (isPrivateHost(hostname))
    throw new Error(`${label} cannot target a private or loopback host`);
  return parsed.toString();
}

function parseIPv4(hostname) {
  const parts = hostname.split(".");
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part)))
    return null;
  const octets = parts.map(Number);
  return octets.every((octet) => octet >= 0 && octet <= 255) ? octets : null;
}

function parseIPv6(hostname) {
  let value = hostname.toLowerCase();
  if (value.includes(".")) {
    const separator = value.lastIndexOf(":");
    const ipv4 = parseIPv4(value.slice(separator + 1));
    if (!ipv4) return null;
    const high = ((ipv4[0] << 8) | ipv4[1]).toString(16);
    const low = ((ipv4[2] << 8) | ipv4[3]).toString(16);
    value = `${value.slice(0, separator + 1)}${high}:${low}`;
  }
  const halves = value.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const groups =
    halves.length === 2
      ? [...left, ...Array(8 - left.length - right.length).fill("0"), ...right]
      : left;
  if (
    groups.length !== 8 ||
    groups.some((group) => !/^[0-9a-f]{1,4}$/.test(group))
  )
    return null;
  return groups.reduce(
    (number, group) => (number << 16n) + BigInt(parseInt(group, 16)),
    0n,
  );
}

function ipv4IsNonPublic(octets) {
  const [first, second, third] = octets;
  return (
    first === 0 ||
    first === 10 ||
    (first === 100 && second >= 64 && second <= 127) ||
    first === 127 ||
    (first === 169 && second === 254) ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 0) ||
    (first === 192 && second === 2) ||
    (first === 192 && second === 88 && third === 99) ||
    (first === 192 && second === 168) ||
    (first === 198 && second >= 18 && second <= 19) ||
    (first === 198 && second === 51 && third === 100) ||
    (first === 203 && second === 0 && third === 113) ||
    first >= 224
  );
}

function ipv6InRange(value, prefix, bits) {
  const prefixValue = parseIPv6(prefix);
  if (prefixValue === null) return false;
  const mask =
    bits === 0 ? 0n : ((1n << 128n) - 1n) ^ ((1n << BigInt(128 - bits)) - 1n);
  return (value & mask) === (prefixValue & mask);
}

function isPrivateHost(hostname) {
  if (
    ["localhost", "metadata.google.internal"].includes(hostname) ||
    hostname.endsWith(".localhost") ||
    hostname.endsWith(".local") ||
    hostname.endsWith(".internal")
  )
    return true;
  if (isIP(hostname) === 4) return ipv4IsNonPublic(parseIPv4(hostname));
  if (isIP(hostname) === 6) {
    const value = parseIPv6(hostname);
    if (value === null) return true;
    if (value >> 32n === 0xffffn) {
      const embedded = Number(value & 0xffffffffn);
      const octets = [
        (embedded >>> 24) & 255,
        (embedded >>> 16) & 255,
        (embedded >>> 8) & 255,
        embedded & 255,
      ];
      if (ipv4IsNonPublic(octets)) return true;
    }
    return (
      ipv6InRange(value, "::", 96) ||
      ipv6InRange(value, "64:ff9b::", 96) ||
      ipv6InRange(value, "64:ff9b:1::", 48) ||
      ipv6InRange(value, "fc00::", 7) ||
      ipv6InRange(value, "fe80::", 10) ||
      ipv6InRange(value, "2001::", 23) ||
      ipv6InRange(value, "2001:db8::", 32) ||
      ipv6InRange(value, "2002::", 16) ||
      ipv6InRange(value, "3fff::", 20) ||
      ipv6InRange(value, "ff00::", 8)
    );
  }
  return false;
}

function requireObject(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error(`${label} must be an object`);
}

function rejectUnknownKeys(value, allowed, label) {
  for (const key of Object.keys(value))
    if (!allowed.has(key))
      throw new Error(`${label} contains unsupported field ${key}`);
}

function requireDateTime(value, label) {
  const match = typeof value === "string" ? value.match(RFC3339_PATTERN) : null;
  if (!match) throw new Error(`${label} must be an RFC 3339 date-time`);
  const [
    ,
    yearText,
    monthText,
    dayText,
    hourText,
    minuteText,
    secondText,
    zone,
    offsetSign,
    offsetHourText,
    offsetMinuteText,
  ] = match;
  const [year, month, day, hour, minute, second] = [
    yearText,
    monthText,
    dayText,
    hourText,
    minuteText,
    secondText,
  ].map(Number);
  const offsetHour = Number(offsetHourText ?? 0);
  const offsetMinute = Number(offsetMinuteText ?? 0);
  const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const daysInMonth = [
    31,
    leapYear ? 29 : 28,
    31,
    30,
    31,
    30,
    31,
    31,
    30,
    31,
    30,
    31,
  ];
  const validDate =
    month >= 1 && month <= 12 && day >= 1 && day <= daysInMonth[month - 1];
  const validTime = hour <= 23 && minute <= 59 && second <= 59;
  const validOffset =
    zone === "Z" ||
    (["+", "-"].includes(offsetSign) && offsetHour <= 23 && offsetMinute <= 59);
  if (!validDate || !validTime || !validOffset)
    throw new Error(`${label} must be an RFC 3339 date-time`);
}

function validateAttestationShape(attestation) {
  requireObject(attestation, "attestation");
  rejectUnknownKeys(attestation, ATTESTATION_KEYS, "attestation");
  for (const key of ATTESTATION_KEYS)
    if (typeof attestation[key] !== "string" || attestation[key].length === 0)
      throw new Error(`attestation.${key} is required`);
  if (attestation.algorithm !== "Ed25519")
    throw new Error("attestation.algorithm must be Ed25519");
  if (attestation.context !== ATTESTATION_CONTEXT)
    throw new Error(`attestation.context must be ${ATTESTATION_CONTEXT}`);
  requireBase58Bytes(attestation.publicKey, 32, "attestation.publicKey");
  requireBase58Bytes(attestation.signature, 64, "attestation.signature");
}

async function assertPublicDestination(value, label, lookupImpl = lookupHost) {
  const parsed = new URL(value);
  const hostname = parsed.hostname
    .toLowerCase()
    .replace(/^\[|\]$/g, "")
    .replace(/\.$/, "");
  if (isPrivateHost(hostname)) {
    const error = new Error(
      `${label} cannot target a private or loopback host`,
    );
    error.code = "UNSAFE_DESTINATION";
    throw error;
  }
  if (isIP(hostname)) return;
  const records = await lookupImpl(hostname, { all: true, verbatim: true });
  const addresses = Array.isArray(records)
    ? records.map((record) => record.address || record)
    : [records.address || records];
  if (
    addresses.length === 0 ||
    addresses.some(
      (address) => isIP(String(address).replace(/^\[|\]$/g, "")) === 0,
    )
  )
    throw new Error(`${label} did not resolve to a valid IP address`);
  if (
    addresses.some((address) =>
      isPrivateHost(String(address).replace(/^\[|\]$/g, "")),
    )
  ) {
    const error = new Error(
      `${label} resolves to a private or loopback address`,
    );
    error.code = "UNSAFE_DESTINATION";
    throw error;
  }
}

function networkErrorStatus(error) {
  return error?.code === "UNSAFE_DESTINATION" ? "failed" : "warning";
}

async function discardResponseBody(response) {
  if (typeof response?.body?.cancel === "function")
    await response.body.cancel().catch(() => {});
}

async function fetchPublicUrl(initialUrl, init, options) {
  const { fetchImpl, lookupImpl, label, maxRedirects = 5 } = options;
  let currentUrl = initialUrl;
  for (
    let redirectCount = 0;
    redirectCount <= maxRedirects;
    redirectCount += 1
  ) {
    try {
      currentUrl = requireHttpUrl(currentUrl, label);
    } catch (error) {
      error.code = "UNSAFE_DESTINATION";
      throw error;
    }
    await assertPublicDestination(currentUrl, label, lookupImpl);
    const response = await fetchImpl(currentUrl, {
      ...init,
      redirect: "manual",
    });
    if (![301, 302, 303, 307, 308].includes(response.status)) {
      await discardResponseBody(response);
      return { response, finalUrl: currentUrl };
    }
    const location = response.headers?.get?.("location");
    if (!location) {
      await discardResponseBody(response);
      return { response, finalUrl: currentUrl };
    }
    if (redirectCount === maxRedirects) {
      const error = new Error(`${label} exceeded ${maxRedirects} redirects`);
      error.code = "UNSAFE_DESTINATION";
      await discardResponseBody(response);
      throw error;
    }
    await discardResponseBody(response);
    try {
      currentUrl = new URL(location, currentUrl).toString();
    } catch (error) {
      error.code = "UNSAFE_DESTINATION";
      throw error;
    }
  }
  throw new Error(`${label} redirect verification failed`);
}

function requireBase58Bytes(value, byteLength, label) {
  if (typeof value !== "string" || value.length === 0)
    throw new Error(`${label} must be a Base58 string`);
  const maximumLength = Math.ceil((byteLength * Math.log(256)) / Math.log(58));
  if (value.length > maximumLength)
    throw new Error(
      `${label} is longer than a ${byteLength}-byte Base58 value`,
    );
  let decoded;
  try {
    decoded = decodeBase58(value);
  } catch {
    throw new Error(`${label} must be valid Base58`);
  }
  if (decoded.length !== byteLength)
    throw new Error(`${label} must decode to ${byteLength} bytes`);
}

export function validatePayload(payload) {
  requireObject(payload, "Receipt payload");
  rejectUnknownKeys(payload, PAYLOAD_KEYS, "Receipt payload");
  if (
    typeof payload.projectTitle !== "string" ||
    payload.projectTitle.length < 3 ||
    payload.projectTitle.length > MAX_TITLE_LENGTH
  )
    throw new Error(
      `projectTitle must be between 3 and ${MAX_TITLE_LENGTH} characters`,
    );
  if (
    typeof payload.projectDescription !== "string" ||
    payload.projectDescription.length < 10 ||
    payload.projectDescription.length > MAX_DESCRIPTION_LENGTH
  )
    throw new Error(
      `projectDescription must be between 10 and ${MAX_DESCRIPTION_LENGTH} characters`,
    );
  requireObject(payload.repository, "repository");
  rejectUnknownKeys(payload.repository, REPOSITORY_KEYS, "repository");
  const repositoryUrl = requireHttpUrl(
    payload.repository.url,
    "repository.url",
  );
  const repository = new URL(repositoryUrl);
  if (repository.protocol !== "https:")
    throw new Error("repository.url must use https");
  if (repository.port)
    throw new Error("repository.url must not use a custom port");
  const repositoryHost = repository.hostname.toLowerCase();
  if (repositoryHost !== "github.com" && repositoryHost !== "www.github.com")
    throw new Error("repository.url must be a GitHub URL in v1");
  const repositoryParts = repository.pathname.split("/").filter(Boolean);
  if (repositoryParts.length !== 2 || repository.search || repository.hash)
    throw new Error("repository.url must point to a GitHub repository");
  const repositoryName = repositoryParts[1].replace(/\.git$/i, "");
  if (
    !GITHUB_SEGMENT_PATTERN.test(repositoryParts[0]) ||
    !GITHUB_SEGMENT_PATTERN.test(repositoryName) ||
    repositoryName.length === 0
  )
    throw new Error(
      "repository.url contains an invalid GitHub owner or repository name",
    );
  if (
    typeof payload.repository.commit !== "string" ||
    !/^[0-9a-f]{40}$/i.test(payload.repository.commit)
  )
    throw new Error("repository.commit must be a 40-character Git SHA");
  requireObject(payload.solana, "solana");
  rejectUnknownKeys(payload.solana, SOLANA_KEYS, "solana");
  if (!["mainnet", "devnet", "testnet"].includes(payload.solana.cluster))
    throw new Error("solana.cluster must be mainnet, devnet, or testnet");
  requireHttpUrl(payload.solana.rpcUrl, "solana.rpcUrl");
  if (Object.hasOwn(payload.solana, "transactionSignature"))
    requireBase58Bytes(
      payload.solana.transactionSignature,
      64,
      "transactionSignature",
    );
  if (Object.hasOwn(payload.solana, "programId"))
    requireBase58Bytes(payload.solana.programId, 32, "programId");
  if (Object.hasOwn(payload.solana, "memo")) {
    if (typeof payload.solana.memo !== "string" || payload.solana.memo.length === 0)
      throw new Error("solana.memo must be a non-empty string");
    if (payload.solana.memo.length > 256)
      throw new Error("solana.memo must not exceed 256 characters");
  }
  if (Object.hasOwn(payload, "demoUrl"))
    requireHttpUrl(payload.demoUrl, "demoUrl");
  if (Object.hasOwn(payload, "verifiedBuildUrl"))
    requireHttpUrl(payload.verifiedBuildUrl, "verifiedBuildUrl");
  requireDateTime(payload.createdAt, "createdAt");
  if (
    typeof payload.receiptId !== "string" ||
    !UUID_PATTERN.test(payload.receiptId)
  )
    throw new Error("receiptId must be a UUID");
  return true;
}

function validateEnvelopeShape(envelope) {
  requireObject(envelope, "Receipt envelope");
  rejectUnknownKeys(envelope, ENVELOPE_KEYS, "Receipt envelope");
  if (envelope.version !== 1) throw new Error("version must be 1");
  if (
    typeof envelope.receiptHash !== "string" ||
    !SHA256_PATTERN.test(envelope.receiptHash)
  )
    throw new Error(
      "receiptHash must be a 64-character lowercase SHA-256 hash",
    );
  if (Object.hasOwn(envelope, "attestation"))
    validateAttestationShape(envelope.attestation);
}

export function createPayload(input = {}) {
  const cluster = input.cluster ?? "devnet";
  const payload = withoutEmptyValues({
    projectTitle: input.projectTitle,
    projectDescription: input.projectDescription,
    repository: {
      url: input.repositoryUrl,
      commit: input.commit,
    },
    solana: {
      cluster,
      rpcUrl: input.rpcUrl ?? DEFAULT_RPC[cluster],
      transactionSignature: input.transactionSignature,
      programId: input.programId,
      memo: input.memo,
    },
    demoUrl: input.demoUrl,
    verifiedBuildUrl: input.verifiedBuildUrl,
    createdAt: input.createdAt ?? new Date().toISOString(),
    receiptId: input.receiptId ?? randomUUID(),
  });
  validatePayload(payload);
  return payload;
}

export function createEnvelope(payload, attestation) {
  validatePayload(payload);
  const envelope = {
    version: 1,
    payload,
    receiptHash: sha256(hashablePayload(payload)),
  };
  if (attestation) {
    validateAttestationShape(attestation);
    envelope.attestation = attestation;
  }
  return envelope;
}

function publicKeyObject(rawPublicKey) {
  const bytes = decodeBase58(rawPublicKey);
  if (bytes.length !== 32)
    throw new Error("Solana public key must decode to 32 bytes");
  return createPublicKey({
    key: Buffer.concat([PUBLIC_KEY_PREFIX, bytes]),
    format: "der",
    type: "spki",
  });
}

export function verifyAttestation(envelope) {
  const attestation = envelope.attestation;
  if (!attestation)
    return { status: "not_checked", message: "No wallet attestation supplied" };
  if (
    typeof attestation.publicKey !== "string" ||
    typeof attestation.signature !== "string"
  )
    return {
      status: "failed",
      message: "Wallet attestation fields are malformed",
    };
  if (attestation.algorithm !== "Ed25519")
    return {
      status: "failed",
      message: "Unsupported wallet attestation algorithm",
    };
  if (attestation.context !== ATTESTATION_CONTEXT)
    return {
      status: "failed",
      message: "Unsupported wallet attestation context",
    };
  try {
    requireBase58Bytes(attestation.publicKey, 32, "attestation.publicKey");
    requireBase58Bytes(attestation.signature, 64, "attestation.signature");
    const valid = verify(
      null,
      attestationBytes(envelope.payload),
      publicKeyObject(attestation.publicKey),
      decodeBase58(attestation.signature),
    );
    return valid
      ? { status: "verified", message: "Wallet signature is valid" }
      : { status: "failed", message: "Wallet signature is invalid" };
  } catch (error) {
    return { status: "failed", message: error.message };
  }
}

export async function signEnvelope(envelope, keypairPath) {
  try {
    validatePayload(envelope?.payload);
    validateEnvelopeShape(envelope);
    if (envelope.version !== 1)
      throw new Error("Receipt version 1 is required");
  } catch (error) {
    throw new Error(`Refusing to sign: ${error.message}`);
  }
  if (!envelope?.payload || envelope.receiptHash !== sha256(hashablePayload(envelope.payload))) {
    throw new Error(
      "Refusing to sign: receipt hash does not match the canonical payload",
    );
  }
  const keypairMetadata = await stat(keypairPath);
  if (
    !keypairMetadata.isFile() ||
    keypairMetadata.size > MAX_KEYPAIR_FILE_BYTES
  )
    throw new Error("Keypair file is missing or exceeds the expected size");
  const keypair = JSON.parse(await readFile(keypairPath, "utf8"));
  if (
    !Array.isArray(keypair) ||
    (keypair.length !== 32 && keypair.length !== 64) ||
    keypair.some((n) => !Number.isInteger(n) || n < 0 || n > 255)
  ) {
    throw new Error(
      "Keypair must be a Solana CLI JSON array of 32 or 64 bytes",
    );
  }
  const seed = Buffer.from(keypair.slice(0, 32));
  const privateKey = createPrivateKey({
    key: Buffer.concat([PRIVATE_KEY_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
  const derivedPublicBytes = createPublicKey(privateKey)
    .export({ format: "der", type: "spki" })
    .subarray(-32);
  if (
    keypair.length === 64 &&
    !Buffer.from(keypair.slice(32)).equals(derivedPublicBytes)
  ) {
    throw new Error("Keypair public key does not match its private seed");
  }
  const publicBytes = derivedPublicBytes;
  const signature = sign(null, attestationBytes(envelope.payload), privateKey);
  return {
    ...envelope,
    attestation: {
      publicKey: encodeBase58(publicBytes),
      signature: encodeBase58(signature),
      algorithm: "Ed25519",
      context: ATTESTATION_CONTEXT,
    },
  };
}

function githubApiUrl(repositoryUrl, commit) {
  const parsed = new URL(repositoryUrl);
  const parts = parsed.pathname.split("/").filter(Boolean);
  if (parts.length < 2)
    throw new Error("GitHub repository URL must include owner and repository");
  return `https://api.github.com/repos/${parts[0]}/${parts[1].replace(/\.git$/i, "")}/commits/${encodeURIComponent(commit)}`;
}

async function fetchJson(url, init = {}, timeoutMs = 10000, fetchImpl = fetch) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImpl(url, {
      ...init,
      signal: controller.signal,
    });
    let body = null;
    const contentLength = Number(response.headers?.get?.("content-length"));
    if (Number.isFinite(contentLength) && contentLength > MAX_RESPONSE_BYTES)
      throw new Error(`Response exceeded ${MAX_RESPONSE_BYTES} bytes`);
    let text = null;
    const reader = response.body?.getReader?.();
    if (reader) {
      const chunks = [];
      let total = 0;
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value?.byteLength || 0;
        if (total > MAX_RESPONSE_BYTES) {
          await reader.cancel().catch(() => {});
          throw new Error(`Response exceeded ${MAX_RESPONSE_BYTES} bytes`);
        }
        chunks.push(Buffer.from(value));
      }
      text = Buffer.concat(chunks).toString("utf8");
    } else if (typeof response.arrayBuffer === "function") {
      const bytes = new Uint8Array(await response.arrayBuffer());
      if (bytes.byteLength > MAX_RESPONSE_BYTES)
        throw new Error(`Response exceeded ${MAX_RESPONSE_BYTES} bytes`);
      text = new TextDecoder().decode(bytes);
    } else if (typeof response.json === "function") {
      try {
        body = await response.json();
      } catch {
        body = null;
      }
    } else if (typeof response.text === "function") {
      text = await response.text();
      if (Buffer.byteLength(text, "utf8") > MAX_RESPONSE_BYTES)
        throw new Error(`Response exceeded ${MAX_RESPONSE_BYTES} bytes`);
    }
    if (text !== null) {
      try {
        body = text ? JSON.parse(text) : null;
      } catch {
        body = text;
      }
    }
    return { response, body };
  } finally {
    clearTimeout(timeout);
  }
}

export async function verifyNetwork(envelope, options = {}) {
  validatePayload(envelope?.payload);
  validateEnvelopeShape(envelope);
  if (envelope.receiptHash !== sha256(hashablePayload(envelope.payload)))
    throw new Error("Network verification requires a valid local receipt hash");
  const checks = [];
  const payload = envelope.payload;
  const fetchImpl = options.fetchImpl || fetch;
  const lookupImpl = options.lookupImpl || lookupHost;
  try {
    const githubUrl = githubApiUrl(
      payload.repository.url,
      payload.repository.commit,
    );
    await assertPublicDestination(githubUrl, "GitHub API", lookupImpl);
    const result = await fetchJson(
      githubUrl,
      {
        redirect: "error",
        headers: {
          accept: "application/vnd.github+json",
          "user-agent": "solana-ship-receipt/0.1",
        },
      },
      10000,
      fetchImpl,
    );
    const resolvedSha =
      typeof result.body?.sha === "string" ? result.body.sha.toLowerCase() : "";
    const requestedSha = payload.repository.commit.toLowerCase();
    const matches = result.response.ok && resolvedSha === requestedSha;
    checks.push({
      name: "github_commit",
      status: matches ? "verified" : "failed",
      message: matches
        ? `Commit resolves to ${resolvedSha}`
        : result.response.ok
          ? "GitHub returned a different commit SHA"
          : `GitHub returned HTTP ${result.response.status}`,
    });
  } catch (error) {
    checks.push({
      name: "github_commit",
      status: networkErrorStatus(error),
      message: `GitHub check unavailable: ${error.message}`,
    });
  }

  if (payload.solana.transactionSignature || payload.solana.programId) {
    const rpcUrl = payload.solana.rpcUrl || DEFAULT_RPC[payload.solana.cluster];
    try {
      await assertPublicDestination(rpcUrl, "Solana RPC", lookupImpl);
      const method = payload.solana.transactionSignature
        ? "getTransaction"
        : "getAccountInfo";
      const params = payload.solana.transactionSignature
        ? [
            payload.solana.transactionSignature,
            { commitment: "confirmed", maxSupportedTransactionVersion: 0 },
          ]
        : [
            payload.solana.programId,
            { commitment: "confirmed", encoding: "base64" },
          ];
      const result = await fetchJson(
        rpcUrl,
        {
          method: "POST",
          redirect: "error",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
        },
        10000,
        fetchImpl,
      );
      const rpcValue =
        method === "getAccountInfo"
          ? result.body?.result?.value
          : result.body?.result;
      const present =
        result.response.ok &&
        rpcValue !== null &&
        rpcValue !== undefined &&
        !result.body?.error;
      if (!present) {
        checks.push({
          name: "solana_state",
          status: "failed",
          message: "Solana RPC did not return the requested state",
        });
      } else if (method === "getTransaction") {
        const details = {};
        if (Number.isInteger(rpcValue.slot)) details.slot = rpcValue.slot;
        if (Number.isInteger(rpcValue.blockTime))
          details.blockTime = rpcValue.blockTime;
        const hasExecutionStatus =
          rpcValue.meta &&
          typeof rpcValue.meta === "object" &&
          !Array.isArray(rpcValue.meta) &&
          Object.hasOwn(rpcValue.meta, "err");
        if (!hasExecutionStatus) {
          details.executionStatus = "unknown";
          checks.push({
            name: "solana_state",
            status: "failed",
            message: "getTransaction response did not include execution status",
            details,
          });
        } else {
          const executionError = rpcValue.meta.err;
          details.executionStatus =
            executionError === null ? "succeeded" : "failed";
          checks.push({
            name: "solana_state",
            status: executionError === null ? "verified" : "failed",
            message:
              executionError === null
                ? "getTransaction returned a confirmed successful transaction"
                : "getTransaction reported an execution error",
            details,
          });
        }
      } else {
        const details = {};
        if (typeof rpcValue.owner === "string") details.owner = rpcValue.owner;
        if (typeof rpcValue.executable === "boolean")
          details.executable = rpcValue.executable;
        if (Number.isSafeInteger(rpcValue.lamports))
          details.lamports = rpcValue.lamports;
        const executable = rpcValue.executable === true;
        checks.push({
          name: "solana_state",
          status: executable ? "verified" : "failed",
          message: executable
            ? "getAccountInfo returned an executable program account"
            : "getAccountInfo did not return an executable program account",
          details,
        });
      }
    } catch (error) {
      checks.push({
        name: "solana_state",
        status: networkErrorStatus(error),
        message: `Solana check unavailable: ${error.message}`,
      });
    }
  } else {
    checks.push({
      name: "solana_state",
      status: "not_checked",
      message: "No transaction signature or program ID supplied",
    });
  }

  if (payload.verifiedBuildUrl) {
    try {
      let fetched = await fetchPublicUrl(
        payload.verifiedBuildUrl,
        { method: "HEAD", signal: AbortSignal.timeout(10000) },
        { fetchImpl, lookupImpl, label: "verifiedBuildUrl" },
      );
      if (fetched.response.status === 405 || fetched.response.status === 501) {
        fetched = await fetchPublicUrl(
          payload.verifiedBuildUrl,
          {
            method: "GET",
            signal: AbortSignal.timeout(10000),
            headers: { range: "bytes=0-0" },
          },
          { fetchImpl, lookupImpl, label: "verifiedBuildUrl" },
        );
      }
      checks.push({
        name: "verified_build",
        status: fetched.response.ok ? "verified" : "failed",
        message: `Verified-build endpoint returned HTTP ${fetched.response.status} at ${fetched.finalUrl}`,
      });
    } catch (error) {
      checks.push({
        name: "verified_build",
        status: networkErrorStatus(error),
        message: `Verified-build check unavailable: ${error.message}`,
      });
    }
  } else {
    checks.push({
      name: "verified_build",
      status: "not_checked",
      message: "No verified-build URL supplied",
    });
  }

  if (payload.demoUrl) {
    try {
      let fetched = await fetchPublicUrl(
        payload.demoUrl,
        { method: "HEAD", signal: AbortSignal.timeout(10000) },
        { fetchImpl, lookupImpl, label: "demoUrl" },
      );
      if (fetched.response.status === 405 || fetched.response.status === 501) {
        fetched = await fetchPublicUrl(
          payload.demoUrl,
          {
            method: "GET",
            signal: AbortSignal.timeout(10000),
            headers: { range: "bytes=0-0" },
          },
          { fetchImpl, lookupImpl, label: "demoUrl" },
        );
      }
      checks.push({
        name: "demo_url",
        status: fetched.response.ok ? "verified" : "failed",
        message: `Demo returned HTTP ${fetched.response.status} at ${fetched.finalUrl}`,
      });
    } catch (error) {
      checks.push({
        name: "demo_url",
        status: networkErrorStatus(error),
        message: `Demo check unavailable: ${error.message}`,
      });
    }
  } else {
    checks.push({
      name: "demo_url",
      status: "not_checked",
      message: "No demo URL supplied",
    });
  }
  return checks;
}

export async function verifyEnvelope(envelope, options = {}) {
  const checks = [];
  const versionIsSupported = envelope?.version === 1;
  checks.push({
    name: "version",
    status: versionIsSupported ? "verified" : "failed",
    message: versionIsSupported
      ? "Receipt version 1 is supported"
      : "Unsupported or missing receipt version",
  });
  let payloadIsUsable = true;
  let schemaIsValid = true;
  let schemaError;
  let receiptHashIsValid = false;
  try {
    validatePayload(envelope?.payload);
  } catch (error) {
    payloadIsUsable = false;
    schemaIsValid = false;
    schemaError = error;
  }
  try {
    validateEnvelopeShape(envelope);
  } catch (error) {
    schemaIsValid = false;
    schemaError ||= error;
  }
  checks.push({
    name: "schema",
    status: schemaIsValid ? "verified" : "failed",
    message: schemaIsValid ? "Receipt schema is valid" : schemaError.message,
  });
  if (payloadIsUsable) {
    const expectedHash = sha256(hashablePayload(envelope.payload));
    receiptHashIsValid = envelope.receiptHash === expectedHash;
    checks.push({
      name: "receipt_hash",
      status: receiptHashIsValid ? "verified" : "failed",
      message: receiptHashIsValid
        ? "Receipt hash matches canonical payload"
        : "Receipt hash does not match canonical payload",
    });
    checks.push({ name: "attestation", ...verifyAttestation(envelope) });
    const memoValue = envelope?.payload?.solana?.memo;
    if (memoValue === undefined || memoValue === null || memoValue === "") {
      checks.push({
        name: "solana_memo",
        status: "not_checked",
        message: "No Solana memo anchor supplied",
      });
    } else {
      const expectedMemoHash = sha256(hashablePayload(envelope.payload));
      const memoMatches = memoValue === expectedMemoHash;
      checks.push({
        name: "solana_memo",
        status: memoMatches ? "verified" : "failed",
        message: memoMatches
          ? "Solana memo matches the canonical payload hash used for anchoring"
          : "Solana memo does not match the canonical payload hash used for anchoring",
      });
    }
  } else {
    checks.push({
      name: "receipt_hash",
      status: "failed",
      message: "Cannot calculate a trustworthy hash for an invalid payload",
    });
    checks.push({
      name: "attestation",
      status: "not_checked",
      message: "Attestation skipped because the payload is invalid",
    });
    checks.push({
      name: "solana_memo",
      status: "not_checked",
      message: "Memo check skipped because the payload is invalid",
    });
  }
  if (options.network) {
    if (versionIsSupported && schemaIsValid && receiptHashIsValid) {
      checks.push(...(await verifyNetwork(envelope, options)));
    } else {
      checks.push(
        ...["github_commit", "solana_state", "demo_url"].map((name) => ({
          name,
          status: "not_checked",
          message:
            "Network checks skipped because local receipt integrity failed",
        })),
      );
    }
  }
  const passed = checks.every((check) => check.status !== "failed");
  const now = options.now || (() => new Date());
  return { passed, verifiedAt: now().toISOString(), checks };
}

export function renderHtml(envelope, result) {
  const escape = (value) =>
    String(value ?? "").replace(
      /[&<>\"']/g,
      (char) =>
        ({
          "&": "&amp;",
          "<": "&lt;",
          ">": "&gt;",
          '"': "&quot;",
          "'": "&#39;",
        })[char],
    );
  const statusLabel = (status) =>
    status === "not_checked"
      ? "Not checked"
      : `${status.charAt(0).toUpperCase()}${status.slice(1)}`;
  const checkLabel = (name) =>
    String(name)
      .split("_")
      .map((part) => `${part.charAt(0).toUpperCase()}${part.slice(1)}`)
      .join(" ");
  const externalLink = (href, label) =>
    `<a href="${escape(href)}" target="_blank" rel="noreferrer noopener" aria-label="${escape(label)} (opens in a new tab)">${escape(label)}</a>`;
  const counts = { verified: 0, warning: 0, failed: 0, not_checked: 0 };
  for (const item of result.checks)
    if (Object.hasOwn(counts, item.status)) counts[item.status] += 1;
  const rows = result.checks
    .map(
      (item) => `<tr>
<th scope="row">${escape(checkLabel(item.name))}</th>
<td><span class="status-badge ${escape(item.status)}"><span aria-hidden="true" class="status-dot"></span>${escape(statusLabel(item.status))}</span></td>
<td><p>${escape(item.message)}</p>${item.details ? `<pre><code>${escape(JSON.stringify(item.details, null, 2))}</code></pre>` : ""}</td>
</tr>`,
    )
    .join("\n");
  const repositoryUrl = envelope.payload.repository.url
    .replace(/\/$/, "")
    .replace(/\.git$/i, "");
  const commitUrl = `${repositoryUrl}/commit/${encodeURIComponent(envelope.payload.repository.commit)}`;
  const clusterQuery =
    envelope.payload.solana.cluster === "mainnet"
      ? ""
      : `?cluster=${encodeURIComponent(envelope.payload.solana.cluster)}`;
  const explorerBase = "https://explorer.solana.com";
  const overallStatus = result.passed ? "verified" : "failed";
  const overallTitle = result.passed
    ? "Receipt checks completed"
    : "Receipt needs review";
  const overallMessage = result.passed
    ? `${counts.verified} verified, ${counts.warning} warnings, ${counts.not_checked} not checked`
    : `${counts.failed} failed, ${counts.warning} warnings, ${counts.not_checked} not checked`;
  const checkStatus = (name) =>
    result.checks.find((check) => check.name === name)?.status || "not_checked";
  const walletAddress = envelope.attestation?.publicKey || "No wallet connected";
  const walletBadge = walletAddress.length > 18
    ? `${walletAddress.slice(0, 8)}...${walletAddress.slice(-6)}`
    : walletAddress;
  const attestationSignature = envelope.attestation?.signature || "No wallet signature supplied";
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="description" content="Verification receipt for ${escape(envelope.payload.projectTitle)}">
<title>${escape(envelope.payload.projectTitle)} · Verification Receipt</title>
<style>
@keyframes fadeUp{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
@keyframes verified-pulse{0%,100%{box-shadow:0 0 0 0 rgba(20,241,149,0)}50%{box-shadow:0 0 0 5px rgba(20,241,149,.15)}}
:root{
  color-scheme:dark;
  --bg:#0a0a0f;--surface:rgba(17,17,24,.92);--surface-muted:#15151e;
  --text:#f4f3f8;--muted:#92909f;
  --border:rgba(255,255,255,.08);
  --purple:#9945ff;--green:#14f195;
  --verified:#14f195;--verified-bg:rgba(20,241,149,.1);
  --warning:#f5a623;--warning-bg:rgba(245,166,35,.1);
  --failed:#ff6b61;--failed-bg:rgba(255,107,97,.1);
  --unchecked:#6e6e8a;--unchecked-bg:rgba(110,110,138,.1);
  --shadow:0 24px 60px rgba(0,0,0,.35);
}
*{box-sizing:border-box;margin:0}
html{min-height:100%}
body{background:var(--bg);color:var(--text);font:16px/1.55 "Trebuchet MS",Verdana,sans-serif;min-height:100%;background-image:radial-gradient(ellipse at 20% 0%,rgba(153,69,255,.06) 0%,transparent 60%),radial-gradient(ellipse at 80% 100%,rgba(20,241,149,.04) 0%,transparent 50%)}
a{color:var(--green);font-weight:650;text-underline-offset:.18em;transition:color .15s}
a:hover{color:#7afacc;text-decoration-thickness:2px}
a:focus-visible{outline:3px solid rgba(20,241,149,.4);outline-offset:3px;border-radius:3px}
.skip-link{position:absolute;left:1rem;top:-5rem;padding:.7rem 1rem;background:var(--text);color:var(--bg);z-index:2;border-radius:6px;font-weight:700}
.skip-link:focus{top:1rem}
.page{width:min(760px,calc(100% - 2rem));margin:2.5rem auto;animation:fadeUp .5s ease-out both}
.receipt{overflow:hidden;background:var(--surface);border:1px solid var(--border);border-radius:12px;box-shadow:var(--shadow);backdrop-filter:blur(14px);position:relative}
.receipt::before{content:"";position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,var(--purple),var(--green))}
.hero{display:block;padding:2rem;border-bottom:1px solid var(--border);background:transparent}
.eyebrow{display:flex;align-items:center;justify-content:space-between;gap:1rem;margin:0 0 1.25rem;color:var(--muted);font-family:"SFMono-Regular",Consolas,monospace;font-size:.7rem;letter-spacing:.1em}
.eyebrow:after{content:"";padding:.45rem .65rem;border:1px solid var(--border);border-radius:999px;color:var(--green);letter-spacing:0;font-size:.68rem;font-family:"SFMono-Regular",Consolas,monospace}
.hero h1{max-width:none;margin:0;background:linear-gradient(90deg,var(--purple),var(--green));-webkit-background-clip:text;background-clip:text;color:transparent;font-size:2.8rem;font-weight:700;letter-spacing:0}
.lede{max-width:58ch;margin:.8rem 0 0;color:var(--muted);font-size:.98rem;line-height:1.6}
.overall{min-width:0;margin-top:1.5rem;padding:1rem;border:1px solid var(--border);border-radius:8px;background:var(--surface-muted);transition:border-color .2s}
.overall strong{display:block;margin-top:.5rem;font-size:1.05rem}
.overall p{margin:.25rem 0 0;color:var(--muted);font-size:.9rem}
.content{display:grid;min-width:0;gap:1.5rem;padding:1.5rem 2rem}
.content section+section{padding-top:1.5rem;border-top:1px solid var(--border)}
section{min-width:0}
section h2{margin-bottom:.8rem;font-family:"Trebuchet MS",Verdana,sans-serif;font-size:.75rem;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--muted)}
.meta{margin:0 0 1rem;color:var(--muted);font-size:.9rem}
.evidence{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.75rem;border:0;background:transparent;border-radius:0}
.evidence div{display:block;padding:1rem;background:var(--surface-muted);border:1px solid var(--border);border-radius:6px;transition:border-color .2s,transform .2s}
.evidence div:hover{border-color:rgba(20,241,149,.2);transform:translateY(-1px)}
.evidence dt{margin-bottom:.65rem;color:var(--green);font-family:"SFMono-Regular",Consolas,monospace;font-size:.65rem;letter-spacing:.1em;text-transform:uppercase;font-weight:700}
.evidence dd{margin:0;font-family:"SFMono-Regular",Consolas,monospace;font-size:.78rem;line-height:1.6}
.evidence dd a{font-size:.78rem}
.evidence dd code{word-break:break-all;font-size:.75rem}
.status-badge{display:inline-flex;align-items:center;gap:.4rem;border:1px solid var(--border);border-radius:999px;padding:.3rem .65rem;font-family:"SFMono-Regular",Consolas,monospace;font-size:.68rem;font-weight:700;letter-spacing:.04em}
.status-badge.verified{color:var(--green);border-color:rgba(20,241,149,.3);background:var(--verified-bg)}
.status-badge.warning{color:var(--warning);border-color:rgba(245,166,35,.3);background:var(--warning-bg)}
.status-badge.failed{color:var(--failed);border-color:rgba(255,107,97,.3);background:var(--failed-bg)}
.status-badge.not_checked{color:var(--unchecked);border-color:rgba(110,110,138,.3);background:var(--unchecked-bg)}
.status-dot{display:inline-block;width:.45rem;height:.45rem;border-radius:50%;flex-shrink:0}
.status-badge.verified .status-dot{background:var(--green);box-shadow:0 0 6px rgba(20,241,149,.5);animation:verified-pulse 2.4s ease-in-out infinite}
.status-badge.warning .status-dot{background:var(--warning);box-shadow:0 0 6px rgba(245,166,35,.4)}
.status-badge.failed .status-dot{background:var(--failed);box-shadow:0 0 6px rgba(255,107,97,.4)}
.status-badge.not_checked .status-dot{background:var(--unchecked)}
.table-wrap{overflow-x:auto;border:1px solid var(--border);border-radius:6px}
table{width:100%;min-width:690px;border-collapse:collapse;font-size:.88rem}
caption{text-align:left;padding:.7rem 1rem;font-weight:700;font-size:.8rem;letter-spacing:.05em;text-transform:uppercase;color:var(--muted);background:var(--surface-muted);border-bottom:1px solid var(--border)}
th,td{text-align:left;padding:.7rem 1rem;border-bottom:1px solid var(--border);vertical-align:top}
th{font-weight:700;font-size:.8rem;white-space:nowrap;color:var(--muted);background:var(--surface-muted)}
td p{margin:0}
td pre{margin:.4rem 0 0;padding:.6rem .8rem;background:var(--bg);border:1px solid var(--border);border-radius:4px;font-size:.75rem;overflow-x:auto}
.hash{display:block;overflow-wrap:anywhere;padding:1rem 1.1rem;border:1px solid var(--border);border-radius:6px;background:var(--surface-muted);font-family:"SFMono-Regular",Consolas,monospace;font-size:.8rem;line-height:1.7}
.note{margin:0;color:var(--muted);line-height:1.6;font-size:.88rem}
footer{padding:1.25rem 2rem;border-top:1px solid var(--border);color:var(--muted);font-size:.85rem;font-style:italic}
@media(max-width:720px){.hero{padding:1.5rem}.hero h1{font-size:2.25rem}.eyebrow{flex-direction:column;align-items:flex-start}.content{padding:1.5rem}.evidence{grid-template-columns:1fr}.page{width:calc(100% - 1rem);margin:.5rem auto}footer{padding:1.25rem 1.5rem}}
@media(print){:root{--bg:#fff;--surface:#fff;--surface-muted:#f7f9f8;--text:#10231d;--muted:#5d6d67;--border:#d7e0dc;--green:#0a7a55;--purple:#075d42;--verified:#08734f;--verified-bg:#e7f7f0;--warning:#865900;--warning-bg:#fff4cf;--failed:#b42318;--failed-bg:#feeceb;--unchecked:#59666f;--unchecked-bg:#edf1f3;--shadow:none}.receipt{box-shadow:none;backdrop-filter:none}.receipt::before{display:none}.hero h1{background:none;color:var(--text)}.evidence div:hover{transform:none;border-color:var(--border)}}
</style></style>
</head>
<body>
<a class="skip-link" href="#main-content">Skip to receipt</a>
<div class="page">
<main class="receipt" id="main-content">
<header class="hero">
<div><p class="eyebrow">Solana Ship Receipt · v${escape(envelope.version)}</p><h1>${escape(envelope.payload.projectTitle)}</h1><p class="lede">${escape(envelope.payload.projectDescription)}</p></div>
<aside class="overall" aria-live="polite"><span class="status-badge ${overallStatus}"><span aria-hidden="true" class="status-dot"></span>${escape(statusLabel(overallStatus))}</span><strong>${overallTitle}</strong><p>${overallMessage}</p></aside>
</header>
<div class="content">
<section aria-labelledby="evidence-title"><h2 id="evidence-title">Evidence status</h2><dl class="evidence">
<div><dt>Git commit</dt><dd><span class="status-badge ${checkStatus("github_commit")}"><span aria-hidden="true" class="status-dot"></span>${escape(statusLabel(checkStatus("github_commit")))}</span><br>${externalLink(commitUrl, envelope.payload.repository.commit)}</dd></div>
<div><dt>Solana program</dt><dd><span class="status-badge ${checkStatus("solana_state")}"><span aria-hidden="true" class="status-dot"></span>${escape(statusLabel(checkStatus("solana_state")))}</span><br><code>${escape(envelope.payload.solana.programId || "No program ID supplied")}</code></dd></div>
<div><dt>Demo URL</dt><dd><span class="status-badge ${checkStatus("demo_url")}"><span aria-hidden="true" class="status-dot"></span>${escape(statusLabel(checkStatus("demo_url")))}</span><br>${envelope.payload.demoUrl ? externalLink(envelope.payload.demoUrl, envelope.payload.demoUrl) : "No demo URL supplied"}</dd></div>
<div><dt>Memo anchor</dt><dd><span class="status-badge ${checkStatus("solana_memo")}"><span aria-hidden="true" class="status-dot"></span>${escape(statusLabel(checkStatus("solana_memo")))}</span><br><code>${escape(envelope.payload.solana.memo || "No memo anchor supplied")}</code></dd></div>
</dl></section>
<section aria-labelledby="metadata-title"><h2 id="metadata-title">Receipt metadata</h2><dl class="evidence"><div><dt>Receipt hash</dt><dd><code>${escape(envelope.receiptHash)}</code></dd></div><div><dt>Timestamp</dt><dd><time datetime="${escape(envelope.payload.createdAt)}">${escape(envelope.payload.createdAt)}</time></dd></div><div><dt>Chain</dt><dd><code>${escape(envelope.payload.solana.cluster)}</code></dd></div></dl></section>
<section aria-labelledby="verification-title"><h2 id="verification-title">Verification</h2><p class="meta">Checked at <time datetime="${escape(result.verifiedAt)}">${escape(result.verifiedAt)}</time></p><div class="table-wrap"><table><caption>Verification checks</caption><thead><tr><th scope="col">Check</th><th scope="col">Status</th><th scope="col">What the verifier found</th></tr></thead><tbody>${rows}</tbody></table></div></section>
<section aria-labelledby="hash-title"><h2 id="hash-title">Signature panel</h2><code class="hash">Canonical hash: ${escape(envelope.receiptHash)}<br>Wallet signature: ${escape(attestationSignature)}</code><p class="note">This hash binds the canonical receipt payload. A wallet attestation, when present, proves control of the signing key—not project safety or endorsement.</p></section>
</div>
<footer>This receipt proves only the checks listed above. It is not a security audit, financial recommendation, or endorsement.</footer>
</main>
</div>
</body>
</html>`;
}

export { DEFAULT_RPC };
