# Getting Started

This guide takes you from a clean checkout to a reviewer-ready receipt. You do
not need a wallet, Solana CLI, transaction signature, or deployed program for
the first run.

## 1. Check the requirement

Install Node.js 20 or newer, then confirm the version:

```shell
node --version
```

## 2. Clone and install

These commands work in PowerShell, Command Prompt, macOS, and Linux terminals:

```shell
git clone https://github.com/ShipReceipt/Solana-Ship-Receipt.git
cd Solana-Ship-Receipt
npm ci
```

The project currently has no runtime npm dependencies. The install command
still checks that your environment can reproduce the committed package state.

## 3. Create your first receipt

Start with the deterministic public sample:

```shell
node src/cli.mjs sample --out first.receipt.json
node src/cli.mjs verify first.receipt.json
```

The local verification should report the receipt version, schema, and hash as
`verified`. Wallet attestation is `not_checked` because the sample is unsigned.
That is expected and is not a failure.

Render the receipt as a standalone HTML file:

```shell
node src/cli.mjs render first.receipt.json --out first.receipt.html
```

Open `first.receipt.html` in a browser. It does not need a web server or an
internet connection.

To confirm that the pinned commit still exists on GitHub, add `--network`:

```shell
node src/cli.mjs verify first.receipt.json --network
```

## 4. Create a receipt for your project

You need four values:

| Value | Example |
| --- | --- |
| Project title | `My Solana Project` |
| Short description | `A devnet payment reconciliation tool.` |
| Public GitHub repository | `https://github.com/owner/project` |
| Full commit SHA | A 40-character Git commit identifier |

From your project checkout, print the full commit SHA with:

```shell
git rev-parse HEAD
```

If you are using GitHub in a browser, open the specific commit and copy the
40-character value from its commit page or URL. A branch name such as `main`
and a short SHA such as `abc1234` are not accepted because they are not an
immutable, exact revision.

Create the receipt with one cross-platform command:

```shell
node src/cli.mjs create --title "My Solana Project" --description "A concise description of the shipped build." --repo "https://github.com/OWNER/REPOSITORY" --commit "FULL_40_CHARACTER_COMMIT_SHA" --cluster devnet --out my-project.receipt.json
```

Then verify local integrity before querying public services:

```shell
node src/cli.mjs verify my-project.receipt.json
node src/cli.mjs verify my-project.receipt.json --network
```

## 5. Add evidence when you have it

Repository provenance is enough to create a valid receipt. Add optional public
evidence to the `create` command when it is available:

| Option | Evidence |
| --- | --- |
| `--tx SIGNATURE` | A Solana transaction that completed successfully |
| `--program ADDRESS` | An executable Solana program account |
| `--demo URL` | A public HTTP(S) demo endpoint |
| `--rpc URL` | A custom public Solana RPC endpoint |

Omitted evidence is reported as `not_checked`; it is never silently presented
as verified.

Wallet signing is separate and optional. Follow the
[wallet attestation instructions](../README.md#add-a-wallet-attestation) only
when you want to prove control of a local Solana keypair. Never paste a private
key or seed phrase into a receipt, issue, command argument, or CI secret.

### Optional Memo anchor

To anchor the receipt hash on devnet, first read the `receiptHash` from the
receipt JSON, then submit that exact value as a Memo transaction with the
Solana CLI. The CLI reads the keypair locally and sends the transaction directly
to the selected cluster; Ship Receipt never receives the keypair.

```powershell
$receiptHash = (Get-Content my-project.receipt.json | ConvertFrom-Json).receiptHash
solana config set --url devnet
solana transfer --from "$env:USERPROFILE\.config\solana\id.json" --allow-unfunded-recipient --fee-payer "$env:USERPROFILE\.config\solana\id.json" 0.000005 "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr" --with-memo $receiptHash
```

Use the returned transaction signature when creating a new receipt revision:

```powershell
node src/cli.mjs create --title "My Solana Project" --description "A concise description of the shipped build." --repo "https://github.com/OWNER/REPOSITORY" --commit "FULL_40_CHARACTER_COMMIT_SHA" --cluster devnet --memo "$receiptHash" --tx "MEMO_TRANSACTION_SIGNATURE" --out my-project.memo.receipt.json
node src/cli.mjs verify my-project.memo.receipt.json --network
```

The Memo check is verified only when the transaction contains the exact
canonical payload hash. The hosted verifier remains read-only and never submits
transactions.

## 6. Build the reviewer handoff

Create a new reviewer bundle and validate it offline:

```shell
node src/cli.mjs bundle my-project.receipt.json --out-dir reviewer-bundle --network
node src/cli.mjs audit reviewer-bundle --json
```

Send the complete `reviewer-bundle/` directory to the reviewer. It contains the
canonical receipt, point-in-time verification result, standalone HTML view,
and a manifest of artifact hashes.

## Understand the result

| Status | What to do |
| --- | --- |
| `verified` | The named check completed and matched the supplied evidence |
| `not_checked` | Optional evidence was not supplied; add it only if relevant |
| `warning` | A public service was unavailable; retry before final submission |
| `failed` | Fix the named mismatch or invalid input before submitting |

Only `failed` gives the command a non-zero exit status.

## Common problems

### The output file already exists

Receipts and bundles are write-once by design. Choose a new filename or output
directory for the next revision. Do not delete evidence that a reviewer may
already have received.

### The commit SHA is rejected

Run `git rev-parse HEAD` and use all 40 characters. Do not use a tag, branch,
short SHA, pull request number, or commit message.

### GitHub verification returns a warning

Confirm that the repository is public and retry. GitHub availability or API
rate limits can temporarily prevent a network check; a warning is not the same
as verified evidence.

### Solana or demo evidence is `not_checked`

This is expected when `--tx`, `--program`, or `--demo` was not included. The
receipt remains useful for exact GitHub commit provenance.

### A command is unclear

Run:

```shell
node src/cli.mjs --help
```

For security boundaries and deployment limitations, read the
[threat model](THREAT-MODEL.md).
