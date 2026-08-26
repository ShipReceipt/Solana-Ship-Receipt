# Solana Ship Receipt

> A portable, tamper-evident build receipt for Solana project submissions.

Solana Ship Receipt is a dependency-free Node.js CLI that binds a project
submission to an exact Git commit and, when supplied, supporting Solana, demo,
and wallet evidence. It produces machine-readable verification results and a
standalone HTML receipt that a reviewer can inspect without opening the
project's working tree.

The verifier reports each assertion independently as `verified`, `warning`,
`failed`, or `not_checked`. It never turns missing evidence into a successful
check.

## Why this exists

Project submissions often combine a repository link, deployment address,
transaction, demo, and wallet identity without a durable record connecting
them. Links move, branches advance, and screenshots are difficult to audit.

A ship receipt creates a stable handoff:

```text
exact Git commit
      +
optional Solana / demo / wallet evidence
      ↓
canonical receipt + SHA-256 hash
      ↓
verification record + reviewer HTML + manifest
```

## What it verifies

| Evidence | Check |
| --- | --- |
| Receipt structure | Supported envelope version and valid payload fields |
| Receipt integrity | SHA-256 hash of the canonical payload |
| GitHub revision | Exact 40-character commit resolves in the public repository |
| Solana state | Transaction succeeds or the supplied program account is executable |
| Demo URL | Public endpoint responds after bounded, revalidated redirects |
| Wallet attestation | Domain-separated Ed25519 signature is valid |

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

## Requirements

- Node.js 20 or newer
- A public GitHub repository and exact 40-character commit SHA
- Optional: a Solana transaction signature, program address, demo URL, or
  Solana CLI keypair for local signing

There are no runtime npm dependencies.

## Quick start

Clone the repository and run the complete local quality gate:

```powershell
git clone https://github.com/ShipReceipt/Solana-Ship-Receipt.git
cd Solana-Ship-Receipt
npm run check
node src/cli.mjs --version
```

`npm run check` validates source syntax, runs the full test suite, and inspects
the exact npm package contents without publishing anything. No dependency
installation step is required.

The `sample` command uses a pinned public fixture and fixed metadata, so it
produces the same receipt hash on every run.

Create an unsigned receipt:

```powershell
node src/cli.mjs create `
  --title "My Solana Project" `
  --description "A concise description of the shipped build." `
  --repo "https://github.com/OWNER/REPOSITORY" `
  --commit "<exact-40-character-commit-sha>" `
  --cluster devnet `
  --program "<program-address>" `
  --demo "https://example.com" `
  --out ship-receipt.json
```

`--program`, `--tx`, and `--demo` are optional. Use `--rpc` to select a custom
public RPC endpoint. The default cluster is `devnet`.

Verify the receipt locally, then check public evidence:

```powershell
node src/cli.mjs verify ship-receipt.json
node src/cli.mjs verify ship-receipt.json --network
node src/cli.mjs verify ship-receipt.json --network --json
```

Local verification checks the receipt contract, canonical hash, and optional
wallet attestation. `--network` additionally queries GitHub, the configured
Solana RPC endpoint, and the demo URL when present. `--json` is intended for CI
and agent workflows.

Any failed check produces a non-zero exit status.

Generated files are write-once by default. The CLI refuses to replace an
existing receipt, signed receipt, or rendered HTML file; choose a new output
path for a new evidence revision.

## Create a reviewer bundle

The recommended handoff is an immutable reviewer bundle:

```powershell
node src/cli.mjs bundle ship-receipt.json `
  --out-dir reviewer-bundle `
  --network

node src/cli.mjs audit reviewer-bundle --json
```

The generated directory contains:

```text
reviewer-bundle/
├── manifest.json       # SHA-256 allowlist for generated artifacts
├── receipt.html        # standalone human-readable receipt
├── receipt.json        # canonical source receipt
└── verification.json   # point-in-time verification result
```

`bundle` refuses an existing output directory, preventing prior reviewer
evidence from being silently replaced. `audit` works offline: it verifies the
manifest, artifact hashes, receipt envelope, and verification record without
rerunning public network checks.

The versioned receipt contract is documented in
[`schema/receipt-v1.schema.json`](schema/receipt-v1.schema.json).

## Render or serve a receipt

Render a standalone HTML document:

```powershell
node src/cli.mjs render ship-receipt.json --out ship-receipt.html
```

Or start the read-only local viewer:

```powershell
node src/cli.mjs serve ship-receipt.json
node src/cli.mjs serve ship-receipt.json --network --port 8787
```

The viewer binds only to `127.0.0.1` and exposes:

- `/` — reviewer HTML
- `/api/receipt` — canonical receipt JSON
- `/api/verification` — verification result JSON

Only `GET` and `HEAD` are accepted. Responses disable caching, framing,
unneeded browser capabilities, and cross-origin resource use through explicit
security headers.

## Add a wallet attestation

Wallet signing is optional and runs locally. The CLI reads a Solana CLI keypair
only for the signing operation; it does not print, embed, or upload private-key
material.

Verify before signing:

```powershell
node src/cli.mjs verify ship-receipt.json
```

Create a signed sibling receipt:

```powershell
node src/cli.mjs sign ship-receipt.json `
  --keypair "$env:USERPROFILE\.config\solana\id.json"

node src/cli.mjs verify ship-receipt.signed.json
```

The default output is `ship-receipt.signed.json`. The unsigned source is
preserved, and signing refuses to replace either the source receipt or an
existing signed artifact. Signatures use Ed25519 with the
`solana-ship-receipt/v1` domain-separation context.

## CLI reference

```text
create   --title T --description D --repo URL --commit SHA [options]
sign     RECEIPT.json --keypair PATH [--out PATH]
verify   RECEIPT.json [--network] [--json]
render   RECEIPT.json [--out PATH] [--network]
serve    RECEIPT.json [--port PORT] [--network]
bundle   RECEIPT.json --out-dir DIR [--network]
audit    BUNDLE_DIR [--json]
sample   [--out PATH]
```

Run `node src/cli.mjs --help` for the current command summary. Unknown options
fail explicitly instead of being ignored.

## Automation and agent workflows

The [Verify Ship Receipt workflow](.github/workflows/verify-receipt.yml) runs
the test suite, creates a receipt from pinned inputs, performs local and public
verification, builds and audits a reviewer bundle, and uploads the evidence as
a GitHub Actions artifact. It never handles a private key.

The repo-local
[`solana-ship-receipt` skill](skills/solana-ship-receipt/SKILL.md) guides Codex
or Claude through the same test-first, local-first workflow while preserving
existing artifacts and reporting unchecked evidence accurately.

## Fixtures and testing

`fixtures/public-projects/` contains deterministic receipts pinned to public
revisions of Anchor, Metaplex Token Metadata, and Solana Program Library.
Offline tests validate their receipt integrity; public network checks remain
separate because third-party APIs and RPC services may be temporarily
unavailable.

```powershell
npm test
npm run test:coverage
```

The suite covers canonicalization, tamper detection, Ed25519 signing, strict
versioning, Solana address validation, SSRF defenses, redirect handling,
machine-readable output, the local viewer, reviewer bundles, offline audit, and
artifact overwrite protection. `npm run test:coverage` adds Node's built-in
line, branch, and function coverage report.

## Repository layout

| Path | Purpose |
| --- | --- |
| `src/receipt.mjs` | Receipt schema checks, hashing, signing, and verification |
| `src/cli.mjs` | Dependency-free command-line interface |
| `src/viewer.mjs` | Loopback-only read-only HTTP viewer |
| `src/bundle.mjs` | Reviewer bundle generation and offline auditing |
| `schema/` | Versioned JSON Schema contract |
| `fixtures/` | Pinned public receipts used by tests |
| `skills/` | Repo-local Codex and Claude workflow skill |
| `docs/` | Delivery milestones and threat model |

## Security model and limitations

Network verification is read-only. Outbound URLs must use HTTP(S), cannot
contain credentials, and cannot resolve to loopback, private, link-local, or
reserved destinations. Demo redirects are bounded and revalidated at every
hop. JSON responses are capped at 256 KiB and demo response bodies are not
retained. Rendered HTML escapes receipt-controlled values and executes no
scripts.

Important limitations:

- A valid receipt does not mean the referenced code is safe.
- A wallet signature proves control of the signing key, not repository or
  project ownership.
- A Solana RPC response is evidence from that endpoint, not an independent
  consensus proof.
- A verification timestamp records when checks ran; it does not guarantee
  future availability.
- The included server is a local viewer, not a production-hosted verifier.

See the full [threat model](docs/THREAT-MODEL.md) before deploying any hosted
service.

## Project status

This repository contains the local MVP: receipt schema, CLI, verifier, wallet
attestation, public evidence checks, HTML renderer, loopback viewer, reviewer
bundle, offline auditor, fixtures, GitHub Actions workflow, and agent skill.
Future hosted deployment remains gated by the controls documented in the
threat model.

Delivery goals and acceptance criteria are tracked in
[`docs/MILESTONES.md`](docs/MILESTONES.md).

## License

[MIT](LICENSE)
