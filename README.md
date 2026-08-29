# Solana Ship Receipt

A dependency-free, tamper-evident build receipt for Solana project submissions.

Solana Ship Receipt binds a project submission to an exact Git commit and,
when supplied, supporting Solana, demo, and wallet evidence. It produces
machine-readable verification results and a standalone HTML receipt that a
reviewer can inspect without opening the project's working tree.

The verifier reports each assertion independently as `verified`, `warning`,
`failed`, or `not_checked`. Missing evidence is never reported as a successful
check.

## Live instance

https://solana-ship-receipt.onrender.com/

- `/` -- paste or upload a receipt JSON for verification
- `/builder` -- create a receipt from project metadata
- `/review` -- verify a receipt with structured status output
- `/health` -- deployment health check
- `/api/receipt` -- canonical receipt JSON
- `/api/verification` -- verification result JSON
- `/api/verify` -- POST endpoint for machine-readable verification

The hosted instance is a read-only demonstration verifier. It does not sign
receipts, store submissions, or prove project security.

## Quick verification

To test the hosted verifier, open https://solana-ship-receipt.onrender.com/review
and paste any of the following receipts. Each produces 9/9 verified checks
against live Solana infrastructure.

### Solana Ship Receipt (self-referential)

This receipt verifies itself -- the hosted instance is the project, the CI
workflow is the verified build, and the demo URL points back to the verifier.

```json
{
  "version": 1,
  "payload": {
    "projectTitle": "Solana Ship Receipt",
    "projectDescription": "A portable, tamper-evident build receipt for Solana project submissions.",
    "repository": {
      "url": "https://github.com/ShipReceipt/Solana-Ship-Receipt",
      "commit": "de9bdb5183f387cfc8af271c0d5e122be4419581"
    },
    "solana": {
      "cluster": "devnet",
      "rpcUrl": "https://api.devnet.solana.com",
      "programId": "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
      "memo": "51ad1d39b96deac253df7c28f7b57521258fb6e8d557809559df608411736635"
    },
    "demoUrl": "https://solana-ship-receipt.onrender.com",
    "verifiedBuildUrl": "https://github.com/ShipReceipt/Solana-Ship-Receipt/actions/workflows/ci.yml",
    "createdAt": "2026-08-29T00:00:00.000Z",
    "receiptId": "00000000-0000-4000-8000-000000000006"
  },
  "receiptHash": "51ad1d39b96deac253df7c28f7b57521258fb6e8d557809559df608411736635",
  "attestation": {
    "publicKey": "B7BcGPwvLuMkXJaah54kt8XTvCJDNi31ad3ZyJE9DSDd",
    "signature": "5puHS6bNBR3cwWD8aYKsPDFtJgkwpHQKyrwRbMn89vwDNeQDyqm494bDiSgQuqjynhwxbVURyDkS7yk3syAtfVBJ",
    "algorithm": "Ed25519",
    "context": "solana-ship-receipt/v1"
  }
}
```

### Metaplex Token Metadata

```json
{
  "version": 1,
  "payload": {
    "projectTitle": "Metaplex Token Metadata",
    "projectDescription": "A public Metaplex Token Metadata fixture pinned to an exact repository revision and devnet program.",
    "repository": {
      "url": "https://github.com/metaplex-foundation/mpl-token-metadata",
      "commit": "349e061053c6fc5b6b815e03e896e4db57012893"
    },
    "solana": {
      "cluster": "devnet",
      "rpcUrl": "https://api.devnet.solana.com",
      "programId": "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s",
      "memo": "f6574fbbb891ff3439ce5605d4b8698a227791f78fbe2290bf1818b90b05ef96"
    },
    "createdAt": "2026-08-23T00:00:00.000Z",
    "receiptId": "00000000-0000-4000-8000-000000000002",
    "demoUrl": "https://developers.metaplex.com/token-metadata",
    "verifiedBuildUrl": "https://github.com/metaplex-foundation/mpl-token-metadata/actions"
  },
  "receiptHash": "f6574fbbb891ff3439ce5605d4b8698a227791f78fbe2290bf1818b90b05ef96",
  "attestation": {
    "publicKey": "dW1t7BAGwRMnNzitFVq43zLxgrQdYfvHWuF6mFkr9DA",
    "signature": "727yHCVvwVerFipFU3oG3SheEgqeZ5zgRvTcdubMuWFML9KX8psdCrursk96VoMuhKgzt6vnknTrBAR9n8vjJhP",
    "algorithm": "Ed25519",
    "context": "solana-ship-receipt/v1"
  }
}
```

### Solana Program Library (Token)

```json
{
  "version": 1,
  "payload": {
    "projectTitle": "Solana Program Library",
    "projectDescription": "A public Solana Program Library fixture pinned to an exact repository revision and devnet program.",
    "repository": {
      "url": "https://github.com/solana-labs/solana-program-library",
      "commit": "264ca72de06b0c2b45c0b15d298000fe3f82db2e"
    },
    "solana": {
      "cluster": "devnet",
      "rpcUrl": "https://api.devnet.solana.com",
      "programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
      "memo": "3201f9588da899065868d1483182aeac42a9cfe56308e6d3261569efbdaa2082"
    },
    "createdAt": "2026-08-23T00:00:00.000Z",
    "receiptId": "00000000-0000-4000-8000-000000000003",
    "demoUrl": "https://www.solana-program.com/docs/token",
    "verifiedBuildUrl": "https://github.com/solana-labs/solana-program-library/actions"
  },
  "receiptHash": "3201f9588da899065868d1483182aeac42a9cfe56308e6d3261569efbdaa2082",
  "attestation": {
    "publicKey": "dW1t7BAGwRMnNzitFVq43zLxgrQdYfvHWuF6mFkr9DA",
    "signature": "3Gw7zC8EGGuLrbZ6yNDQq7w4tEiPtLkxAQy8MZosdvDinZ4g77XoJa4o6sjj72MfcJVbvhDo12FwqNg8EVvibVxi",
    "algorithm": "Ed25519",
    "context": "solana-ship-receipt/v1"
  }
}
```

### Associated Token Account

```json
{
  "version": 1,
  "payload": {
    "projectTitle": "Associated Token Account Program",
    "projectDescription": "A public Solana Associated Token Account program fixture pinned to an exact repository revision and devnet program.",
    "repository": {
      "url": "https://github.com/solana-program/associated-token-account",
      "commit": "c0c821e7792054c1034ff368f33cc593ccdb425e"
    },
    "solana": {
      "cluster": "devnet",
      "rpcUrl": "https://api.devnet.solana.com",
      "programId": "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
      "memo": "4a2cea421e5864943070e6d050813bf420e742db98f5286d0c8ebeda2c517641"
    },
    "createdAt": "2026-08-28T00:00:00.000Z",
    "receiptId": "00000000-0000-4000-8000-000000000004",
    "demoUrl": "https://www.solana-program.com/docs/associated-token-account",
    "verifiedBuildUrl": "https://github.com/solana-program/associated-token-account/actions"
  },
  "receiptHash": "4a2cea421e5864943070e6d050813bf420e742db98f5286d0c8ebeda2c517641",
  "attestation": {
    "publicKey": "dW1t7BAGwRMnNzitFVq43zLxgrQdYfvHWuF6mFkr9DA",
    "signature": "4hy3P7dKCYWyudxkAL8s2p33yeBPsKN2XDK5zt5j8ZYegwN1NGTDnEXSjDkERFE1rMzEjhFFskSNfELovPnZiYEv",
    "algorithm": "Ed25519",
    "context": "solana-ship-receipt/v1"
  }
}
```

Alternatively, open https://solana-ship-receipt.onrender.com/ and click
"Solana Ship Receipt" in the quick-start section to auto-populate and verify.

## Quick start

Requirements: Node.js 20 or newer and Git.

```shell
git clone https://github.com/ShipReceipt/Solana-Ship-Receipt.git
cd Solana-Ship-Receipt
npm ci
node src/cli.mjs sample --out first.receipt.json
node src/cli.mjs verify first.receipt.json
node src/cli.mjs render first.receipt.json --out first.receipt.html
```

The verification should mark the receipt version, schema, and hash as
`verified`. Wallet attestation is `not_checked` because the sample is
intentionally unsigned. Open `first.receipt.html` in any browser to see the
reviewer-facing result. The sample uses fixed metadata and a pinned public
revision, so its receipt hash is deterministic.

Verify with public network checks:

```shell
node src/cli.mjs verify first.receipt.json --network
```

## Create a receipt for your project

From your project's Git checkout, copy the immutable commit identifier:

```shell
git rev-parse HEAD
```

Then replace the placeholders in this cross-platform command:

```shell
node src/cli.mjs create \
  --title "My Solana Project" \
  --description "A concise description of the shipped build." \
  --repo "https://github.com/OWNER/REPOSITORY" \
  --commit "FULL_40_CHARACTER_COMMIT_SHA" \
  --cluster devnet \
  --out ship-receipt.json
```

Verify local integrity, then query public evidence:

```shell
node src/cli.mjs verify ship-receipt.json
node src/cli.mjs verify ship-receipt.json --network
```

Optional evidence flags: `--program`, `--tx`, `--demo`, `--rpc`,
`--verified-build-url`, `--memo`. Omitted evidence is reported as
`not_checked`. Any failed check produces a non-zero exit status.

Generated files are write-once by default. Choose a new output path for each
evidence revision.

## What it verifies

| Evidence | Check |
| --- | --- |
| Receipt structure | Supported envelope version and valid payload fields |
| Receipt integrity | SHA-256 hash of the canonical payload |
| GitHub revision | Exact 40-character commit resolves in the public repository |
| Solana state | Transaction succeeds or the supplied program account is executable |
| Verified build | CI workflow endpoint responds with HTTP 200 |
| Demo URL | Public endpoint responds after bounded, revalidated redirects |
| Wallet attestation | Domain-separated Ed25519 signature is valid |
| Memo anchor | On-chain memo matches the canonical payload hash |

These checks establish provenance and point-in-time availability. They do not
establish code quality, repository ownership, program safety, or endorsement.

### Status semantics

| Status | Meaning |
| --- | --- |
| `verified` | The verifier completed the named check and the evidence matched |
| `warning` | External service unavailable; the check could not complete |
| `failed` | Evidence was malformed, unsafe, missing, or did not match |
| `not_checked` | Optional evidence was not included in the receipt |

Only `failed` makes the verification result fail and produces a non-zero exit
status. Warnings and unchecked optional evidence remain visible in every
human- and machine-readable result.

## Add a wallet attestation

Wallet signing is optional and runs locally. The CLI reads a Solana CLI keypair
only for the signing operation; it does not print, embed, or upload private-key
material.

```shell
node src/cli.mjs verify ship-receipt.json
node src/cli.mjs sign ship-receipt.json --keypair "$HOME/.config/solana/id.json"
node src/cli.mjs verify ship-receipt.signed.json
```

The default output is `ship-receipt.signed.json`. The unsigned source is
preserved, and signing refuses to replace either the source receipt or an
existing signed artifact. Signatures use Ed25519 with the
`solana-ship-receipt/v1` domain-separation context.

## Create a reviewer bundle

The recommended handoff is an immutable reviewer bundle:

```shell
node src/cli.mjs bundle ship-receipt.json --out-dir reviewer-bundle --network
node src/cli.mjs audit reviewer-bundle --json
```

The generated directory contains:

```text
reviewer-bundle/
  manifest.json       SHA-256 allowlist for generated artifacts
  receipt.html        standalone human-readable receipt
  receipt.json        canonical source receipt
  verification.json   point-in-time verification result
```

`bundle` refuses an existing output directory, preventing prior reviewer
evidence from being silently replaced. `audit` works offline: it verifies the
manifest, artifact hashes, receipt envelope, and verification record without
rerunning public network checks.

## Render or serve a receipt

Render a standalone HTML document:

```shell
node src/cli.mjs render ship-receipt.json --out ship-receipt.html
```

Start the read-only local viewer:

```shell
node src/cli.mjs serve ship-receipt.json
node src/cli.mjs serve ship-receipt.json --network --port 8787
```

The default viewer binds only to `127.0.0.1`. Public hosting requires explicit
opt-in: `--host 0.0.0.0 --public`. See `docs/DEPLOYMENT.md` for the release
gate and operational requirements.

## CLI reference

```text
create   --title T --description D --repo URL --commit SHA [options]
sign     RECEIPT.json --keypair PATH [--out PATH]
verify   RECEIPT.json [--network] [--json]
render   RECEIPT.json [--out PATH] [--network]
serve    RECEIPT.json [--port PORT] [--network] [--host HOST] [--public]
bundle   RECEIPT.json --out-dir DIR [--network]
audit    BUNDLE_DIR [--json]
sample   [--out PATH]
```

Run `node src/cli.mjs --help` for the current command summary. Unknown options
fail explicitly instead of being ignored.

## Security model

Network verification is read-only. Outbound URLs must use HTTP(S), cannot
contain credentials, and cannot resolve to loopback, private, link-local, or
reserved destinations. Demo redirects are bounded and revalidated at every hop.
JSON responses are capped at 256 KiB and demo response bodies are not retained.
Rendered HTML escapes receipt-controlled values and executes no scripts.

Limitations:

- A valid receipt does not mean the referenced code is safe.
- A wallet signature proves control of the signing key, not repository or
  project ownership.
- A Solana RPC response is evidence from that endpoint, not an independent
  consensus proof.
- A verification timestamp records when checks ran; it does not guarantee
  future availability.
- The included server is a read-only verifier deployed publicly for
  demonstration. Production operation requires the controls in
  `docs/DEPLOYMENT.md`.

See the full threat model at `docs/THREAT-MODEL.md` before deploying any hosted
service.

## Fixtures and testing

`fixtures/public-projects/` contains deterministic receipts pinned to public
revisions of six Solana projects:

- Metaplex Token Metadata
- Solana Program Library
- Solana Memo
- Associated Token Account
- Solana Token Program
- Solana Ship Receipt (self-referential)

All fixtures include known devnet executable program accounts and produce
9/9 verified checks against the self-referential receipt.

```shell
npm test
npm run test:coverage
```

The suite covers canonicalization, tamper detection, Ed25519 signing, strict
versioning, Solana address validation, SSRF defenses, redirect handling,
machine-readable output, the local viewer, reviewer bundles, offline audit,
artifact overwrite protection, and fixture network verification.

## Repository layout

| Path | Purpose |
| --- | --- |
| `src/receipt.mjs` | Receipt schema checks, hashing, signing, and verification |
| `src/cli.mjs` | Dependency-free command-line interface |
| `src/viewer.mjs` | Loopback-only read-only HTTP viewer |
| `src/bundle.mjs` | Reviewer bundle generation and offline auditing |
| `src/base58.mjs` | Base58 encode/decode for Solana key material |
| `schema/` | Versioned JSON Schema contract |
| `fixtures/` | Pinned public receipts used by tests |
| `skills/` | Repo-local Codex and Claude workflow skill |
| `docs/` | Beginner guide, milestones, deployment, and threat model |
| `test/` | Unit, security, CLI, viewer, and bundle tests |
| `.github/workflows/` | Cross-version CI, receipt verification, and fixture checks |

## Automation and agent workflows

The verify-receipt workflow runs `npm ci` and the test suite, creates a receipt
from pinned inputs, performs local and public verification, builds and audits a
reviewer bundle, and uploads the evidence as a GitHub Actions artifact. It never
handles a private key.

The verify-fixtures workflow runs weekly to confirm all six fixture receipts
remain verifiable against live Solana infrastructure.

The repo-local `solana-ship-receipt` skill guides Codex or Claude through the
same test-first, local-first workflow while preserving existing artifacts and
reporting unchecked evidence accurately.

## Project status

This repository contains the MVP: receipt schema, CLI, verifier, wallet
attestation, public evidence checks (GitHub, Solana RPC, demo, verified build),
HTML renderer, loopback viewer, hosted reviewer, reviewer bundle, offline
auditor, six fixtures, GitHub Actions workflows, and agent skill. The hosted
Render instance is available for review.

Delivery goals and acceptance criteria are tracked in `docs/MILESTONES.md`.
Builder and reviewer testing protocol is documented in `docs/USER-TESTING.md`.
Contribution and vulnerability-reporting procedures are in `CONTRIBUTING.md`
and `SECURITY.md`.

## License

MIT
