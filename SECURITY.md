# Security Policy

Solana Ship Receipt handles project metadata and optional public evidence. It
does not custody funds, submit transactions, execute repository code, or accept
private keys in CI or hosted workflows.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |

## Reporting a vulnerability

Please report suspected vulnerabilities privately. If GitHub private
vulnerability reporting is enabled, use the repository's
[security advisory form](https://github.com/ShipReceipt/Solana-Ship-Receipt/security/advisories/new).
Do not publish exploit details in a public issue or pull request before a fix
is available.

Include:

- the affected version or commit;
- a clear description and security impact;
- minimal reproduction steps or a proof of concept; and
- any relevant logs with credentials and private data removed.

The maintainers will acknowledge a report when practical, investigate it, and
coordinate disclosure after a fix or mitigation is available. Please do not
include seed phrases, private keys, access tokens, or live customer data in a
report.

## Security boundaries

The verifier's documented trust boundary and mitigations are in
[`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md). In particular, network
verification is read-only and applies URL, DNS, redirect, timeout, and response
size controls. A successful receipt is provenance evidence, not a security
audit, code-safety claim, or endorsement.
