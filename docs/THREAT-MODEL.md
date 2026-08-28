# Threat model

This document defines the security boundary for the local CLI and the
read-only hosted verifier. A demonstration instance is deployed at
https://solana-ship-receipt.onrender.com/. A receipt establishes evidence provenance; it does
not establish that the referenced software is safe.

## Assets

- Receipt payload, canonical hash, and verification result.
- Builder wallet public key and Ed25519 attestation.
- Local Solana CLI keypair used for an optional signature.
- Reviewer availability, integrity, and interpretation of evidence.

## Trust boundaries

1. The builder controls the receipt inputs and the repository contents.
2. GitHub, Solana RPC, and demo hosts are external, untrusted evidence sources.
3. The verifier controls canonicalization, checks, status labels, and output.
4. A hosted verifier must treat every submitted URL and response as hostile.

## Threats and mitigations

### Forged or altered receipt

The payload is canonicalized and hashed. An Ed25519 signature covers a
domain-separated `solana-ship-receipt/v1` context plus the canonical payload.
Verification rejects hash changes, unsupported versions, wrong algorithms, and
wrong public keys.

### Private key exposure

The CLI reads a Solana CLI keypair only during local signing. It never prints,
stores, uploads, or requests a seed phrase. The GitHub Action never signs.
Hosted services must not accept private keys at all. The current hosted
instance is read-only and does not store submitted receipts.

### SSRF and unsafe redirect

Repository, RPC, and demo URLs require HTTP(S), reject credentials, loopback,
private, link-local, and reserved IP literals, and resolve hostnames before a
request. Demo redirects are manual, bounded, and revalidated at every hop.
Hosted deployments must add egress filtering, DNS pinning or equivalent
revalidation, response-size limits, and request timeouts.

### Malicious response or content type

The verifier consumes only bounded JSON/HTTP metadata and never executes code
from a repository, demo, or RPC response. JSON responses are capped at 256 KiB;
demo response bodies are discarded after status and redirect checks. HTML
output escapes all untrusted values. Hosted endpoints must retain
equivalent response limits and reject unexpected content types.

### Replay or stale evidence

The receipt includes an immutable Git commit and creation timestamp. Every
verification result includes `verifiedAt`; reviewers should treat old results
as observations, not current liveness guarantees. A future hosted service may
add an expiry policy, but must not silently rewrite a receipt.

### RPC inconsistency or outage

RPC results are labeled as evidence from a named cluster and endpoint. Null
accounts, missing transactions, HTTP errors, and unavailable checks are not
reported as verified. RPC verification is not a consensus proof or security
audit; high-value use should compare independent endpoints.

### Denial of service

Network checks use timeouts, bounded redirects, small request methods, and no
parallel fan-out. The viewer applies configurable per-client POST,
concurrent-verification, and response byte limits, and emits structured
request logs without receipt contents. Hosted deployments should
add carefully evaluated caching keyed by receipt hash.

## Non-goals

- Security auditing, bug-finding, or endorsement of the referenced project.
- Custody, transaction submission, autonomous wallet operation, or token logic.
- Arbitrary code execution, private repository access, or private-key recovery.
- Proving that a demo is available to every reviewer or that a program is safe.

## Hosted-service release gates

Before hosting a public verifier, require an isolated egress policy, DNS and
redirect revalidation tests, request and response limits, structured audit
logs without secrets, rate limiting, dependency review, and an incident
rollback plan. Do not deploy until these gates and the full test suite pass.
