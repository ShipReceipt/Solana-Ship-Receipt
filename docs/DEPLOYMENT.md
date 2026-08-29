# Public verifier deployment guide

This repository intentionally keeps the default verifier loopback-only. A
public verifier requires an explicit opt-in and a review of the deployment gate
before using `--host 0.0.0.0 --public`.

## Current hosted instance

A demonstration deployment is live at
https://solana-ship-receipt.onrender.com/. Available routes:

- `/` -- paste or upload a receipt JSON for verification
- `/builder` -- create a receipt from project metadata
- `/review` -- verify a receipt with structured status output
- `/health` -- deployment health check (use for platform health probes)
- `/api/receipt` -- canonical receipt JSON
- `/api/verification` -- verification result JSON
- `/api/verify` -- POST endpoint for machine-readable verification

The instance is read-only and does not accept private keys or store submitted
receipts. Treat it as a public demo until the operational controls listed below
are complete.

## GitHub Actions deployment

The manual workflow `.github/workflows/deploy-public-verifier.yml` validates
the test suite, triggers Render, and waits for `/health`. Configure a protected
production-environment secret named `RENDER_DEPLOY_HOOK_URL` with the Render
deploy hook URL. Keep the hook URL out of repository files and workflow output.

To roll back, pause the workflow, select the last known-good commit in the
Render service dashboard, and redeploy it. Confirm `/health`, `/review`, and
`/api/verification` before resuming deployments.

## Release gate

Before exposing the verifier to the public internet, confirm all of the
following:

- The service is read-only and never accepts or stores private keys.
- The service is bound only to the intended public host and requires explicit
  `--public` opt-in.
- Outbound HTTP(S) checks are subject to the same SSRF protections in the repo:
  no credentials, no loopback/private/reserved destinations, and redirect
  validation.
- Response bodies are bounded and untrusted values are escaped in rendered HTML.
- The deployment has rate limiting, concurrency limits, and structured audit
  logs without secrets. The viewer provides configurable per-client POST and
  concurrent-verification limits and emits structured request logs without
  receipt contents.
- The public host is behind a reverse proxy or load balancer with TLS
  termination and a documented rollback plan.
- The service is tested with the same suite in this repository and passes the
  release gate in `docs/THREAT-MODEL.md`.

## Minimal public verifier command

Run the local viewer as a public verifier only after the release gate is
satisfied:

```shell
node src/cli.mjs serve ship-receipt.json --host 0.0.0.0 --port 8787 --network --public
```

This is intentionally different from the default local workflow:

```shell
node src/cli.mjs serve ship-receipt.json
```

The default remains loopback-only and is the safe path for local development.

## Reverse proxy example

A production deployment should place the service behind TLS termination and
keep the application bound to a private listener:

```nginx
server {
  listen 443 ssl http2;
  server_name verifier.example.com;

  location / {
    proxy_pass http://127.0.0.1:8787;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
  }
}
```

This keeps the verifier behind a standard edge layer while preserving the
repo's explicit public-host opt-in requirement in the application itself.

## Operational guidance

- Keep the verifier stateless and single-purpose.
- Do not use the public verifier as a signing endpoint.
- Keep all inbound submissions read-only and ephemeral.
- Keep the deployment logs free of receipt secrets, wallet keys, or full HTTP
  request bodies.
- Treat old verification results as observations, not current liveness
  guarantees.

## Reference

- `docs/THREAT-MODEL.md` for the security boundaries and release gates
- `README.md` for the local CLI workflow
- `src/viewer.mjs` for the bound-host enforcement and public opt-in behavior
