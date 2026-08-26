---
name: solana-ship-receipt
description: Guide safe creation, verification, signing, and reviewer packaging of Solana Ship Receipt provenance evidence for a public project build.
---

# Solana Ship Receipt

Create a receipt that lets a reviewer distinguish cryptographic integrity from
public evidence that was actually checked. Preserve the user's scope and do not
publish artifacts or mutate their application repository without authorization.

## Required evidence

Collect a project title, a concise description, a public GitHub repository URL,
and the exact 40-character commit SHA. Add a Solana cluster plus either a
transaction signature or program account when available. Treat a demo URL and
wallet attestation as optional.

Never request or expose private keys, seed phrases, funds, or tokens. Wallet
signing is local and optional; use only a keypair path the user explicitly
authorizes, and never print or copy the keypair contents.

## Workflow

1. Run `npm test` from the Solana Ship Receipt repository. Stop and explain any
   failure before generating evidence.
2. Create an unsigned receipt with `node src/cli.mjs create`. Use a new output
   filename so existing evidence is preserved.
3. Run local verification before network verification. Resolve local schema,
   hash, and attestation failures before making public network checks.
4. Run `node src/cli.mjs verify RECEIPT.json --network --json` when the user has
   authorized public GitHub, Solana RPC, and demo checks. Report `not_checked`
   as unknown rather than implying success.
5. If signing was requested, verify the unsigned receipt first, sign locally,
   then verify the generated `.signed.json` receipt. The CLI preserves the
   unsigned source by default, refuses to overwrite it, and refuses to replace
   an existing signed artifact. Signing proves control of a wallet; it does not
   prove code quality, safety, ownership of the repository, or an endorsement.
6. Create a reviewer bundle and audit it with a fresh directory:

   `node src/cli.mjs bundle RECEIPT.json --out-dir REVIEWER_DIR --network`

   `node src/cli.mjs audit REVIEWER_DIR --json`

7. Return the receipt hash, artifact paths, verification outcome, failed or
   unchecked evidence, and the exact commands a reviewer can rerun.

Do not bypass an occupied bundle directory. Do not weaken URL safety checks or
change a receipt after it has been signed; create a new receipt instead.
