# Builder and reviewer testing

This protocol records the user evidence needed for the public MVP. It provides
tasks and questions; participant results must be added after real sessions.
Do not fabricate quotes, completion times, or findings.

## Success criteria

- Five builders complete receipt creation without private-key assistance.
- Two reviewers verify a supplied receipt and explain the status meanings.
- At least three participants describe the same evidence-reconciliation problem.
- A reviewer reaches the correct receipt conclusion in under two minutes.
- No participant is asked to share a seed phrase, private key, or access token.

## Builder sessions

Run five sessions with builders who have a public or test Solana project. Give
each participant the same task:

1. Open the builder flow at `/builder`.
2. Enter a public repository URL and its full commit SHA.
3. Add a devnet program ID or successful transaction signature.
4. Add a demo URL when available.
5. Create and download or copy the resulting receipt.
6. Explain which checks are verified, unchecked, or need review.

Record for each session:

| Field | Result |
| --- | --- |
| Participant ID | Anonymous identifier |
| Completed without help | Yes / No |
| Time to receipt | Minutes and seconds |
| Time to understand status | Minutes and seconds |
| Confusing field | Exact field or step |
| Evidence-reconciliation example | Short paraphrase |
| Private-key boundary understood | Yes / No |
| Suggested change | One actionable improvement |

## Reviewer sessions

Run two sessions with people who review software submissions. Give each
reviewer a receipt bundle and ask:

1. What exact code revision does this receipt describe?
2. Which Solana evidence was checked?
3. What does `not_checked` mean here?
4. Does a passing receipt prove the project is secure?
5. Would you accept this artifact as a reviewer handoff? Why or why not?

Start a timer when the receipt is opened. Stop when the reviewer identifies the
commit, Solana evidence status, and security limitation. Record whether the
result was correct in under two minutes.

## Evidence log

Keep raw notes private when they contain personal information. Commit only
anonymized summaries and aggregate results:

| Session | Role | Correct under 2 min | Completed | Main finding |
| --- | --- | --- | --- | --- |
| B1 | Builder | Pending | Pending | Pending |
| B2 | Builder | Pending | Pending | Pending |
| B3 | Builder | Pending | Pending | Pending |
| B4 | Builder | Pending | Pending | Pending |
| B5 | Builder | Pending | Pending | Pending |
| R1 | Reviewer | Pending | N/A | Pending |
| R2 | Reviewer | Pending | N/A | Pending |

## Follow-up

After the sessions, update this document with aggregate counts and a short
list of changes made in response. Keep participant identities, private keys,
seed phrases, tokens, and private project data out of the repository.
