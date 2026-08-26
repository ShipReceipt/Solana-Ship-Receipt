# Contributing

Thanks for helping improve Solana Ship Receipt. The project is intentionally
small and dependency-free at runtime; changes should preserve that property
unless a design decision and its security implications are documented first.

## Development setup

Requirements:

- Node.js 20 or newer
- npm (the repository lockfile is authoritative)

From a fresh checkout:

```powershell
npm ci
npm run check
```

`npm run check` performs syntax validation, runs the complete test suite, and
prints the exact files that would be included in an npm package. For a focused
run, use `npm test`; `npm run test:coverage` adds Node's built-in coverage
report.

## Change guidelines

- Add or update tests for behavior changes and security fixes.
- Keep receipt output deterministic wherever the input is deterministic.
- Preserve the distinction between `verified`, `warning`, `failed`, and
  `not_checked` evidence.
- Do not weaken URL validation, redirect revalidation, response limits, or
  write-once artifact protection.
- Never commit private keys, seed phrases, tokens, generated receipts, local
  reviewer bundles, coverage output, or other machine-local artifacts.
- Update the README, schema documentation, or threat model when the public
  contract or security boundary changes.

Network checks are deliberately kept separate from deterministic unit tests.
Tests that exercise external services should use bounded fakes or explicit
integration workflows rather than making the default test suite depend on a
third-party service being available.

## Pull requests

A pull request should explain the user-visible behavior, include the relevant
test command and result, and call out any change to the receipt schema or
network trust boundary. Keep commits focused and leave the working tree free
of generated artifacts.

Before requesting review, confirm:

```text
[ ] npm ci succeeds from a clean checkout
[ ] npm run check passes
[ ] documentation matches the implementation
[ ] no secrets or generated evidence files are present
[ ] git diff --check is clean
```
