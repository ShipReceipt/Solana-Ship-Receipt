# Delivery milestones

## Milestone 1 -- Receipt contract and local verifier (23-25 August)

Completed.

- Versioned canonical JSON receipt format with `additionalProperties: false`.
- Deterministic SHA-256 receipt hash and tamper detection.
- Local Ed25519 signing from a Solana CLI keypair with domain separation.
- Local signature verification and reviewer-readable HTML output.
- Automated tests and a public-repository sample.

Acceptance: a clean Node.js 20 installation can create, sign, verify, and render
a receipt without installing application dependencies.

## Milestone 2 -- Public evidence checks (26-31 August)

Completed.

- GitHub commit existence and repository metadata checks.
- Solana transaction/executable-program verification through read-only RPC.
- Demo availability check with explicit failure and unsupported states.
- Verified-build URL check with HEAD/GET fallback and redirect validation.
- SSRF defenses, DNS resolution validation, and redirect bounding.
- Threat model document.

Acceptance: a reviewer can distinguish verified evidence, failed evidence,
warnings, and facts the tool did not check.

## Milestone 3 -- Agentic workflow and CI (1-5 September)

Completed.

- Codex/Claude skill for guided receipt generation.
- GitHub Actions CI workflow with Node 20/22/24 matrix.
- Receipt verification workflow with network checks and artifact upload.
- Fixture verification workflow (weekly) with six pinned public receipts.
- Deploy workflow with pinned action SHAs and persist-credentials: false.
- Hosted read-only receipt viewer at https://solana-ship-receipt.onrender.com/.

Acceptance: a clean checkout can reproduce and verify the same receipt, audit a
reviewer bundle offline, and run the guided workflow without private keys.

## Milestone 4 -- Public MVP and user test (6-10 September)

Completed.

- Open-source release and hosted verifier on Render.
- Six public Solana project receipts (Metaplex, SPL, Memo, ATA, Token, Ship
  Receipt self-referential).
- All six fixtures produce 9/9 verified checks against live infrastructure.
- Builder page with onboarding flow, field hints, and demo buttons.
- Reviewer page with status guide, evidence flow summary, and demo verification.
- Upload page with quick-start demo grid and 3-step onboarding.
- Unified Solana cyberpunk design across all pages.
- User testing protocol documented.
- Production README, deployment guide, and threat model.

Acceptance: five public Solana projects produce receipts that independent
reviewers can verify end-to-end in under two minutes.
