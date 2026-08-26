# Delivery milestones

Approval work began on 23 August 2026. The target remains 10 September 2026,
11:59 PM Africa/Nairobi.

## Milestone 1 - Receipt contract and local verifier (23-25 August)

- Versioned canonical JSON receipt format.
- Deterministic SHA-256 receipt hash and tamper detection.
- Local Ed25519 signing from a Solana CLI keypair.
- Local signature verification and reviewer-readable HTML output.
- Automated tests and a public-repository sample.

Acceptance: a clean Node.js 20 installation can create, sign, verify, and render
a receipt without installing application dependencies.

## Milestone 2 - Public evidence checks (26-31 August)

- GitHub commit existence and repository metadata checks.
- Solana transaction/program-account verification through read-only RPC.
- Demo availability check with explicit failure and unsupported states.
- Verified-build integration spike and threat-model document.

Acceptance: a reviewer can distinguish verified evidence, failed evidence,
warnings, and facts the tool did not check.

## Milestone 3 - Agentic workflow and CI (1-5 September)

- Codex/Claude skill for guided receipt generation.
- GitHub Action that creates a receipt from a pinned commit.
- Fixtures from three public Solana repositories, pinned to exact commits.
- Hosted read-only receipt viewer.

Acceptance: a clean checkout can reproduce and verify the same receipt, audit a
reviewer bundle offline, and run the guided workflow without private keys.

## Milestone 4 - Public MVP and user test (6-10 September)

- Open-source release and hosted verifier.
- Five public devnet project receipts.
- Five builder tests and two reviewer interviews.
- Demo video, limitations, and final delivery evidence.

Primary KPI: five public Solana projects produce receipts that independent
reviewers can verify end-to-end in under two minutes.
