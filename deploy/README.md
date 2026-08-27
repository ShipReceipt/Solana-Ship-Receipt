# Public verifier deployment scaffold

This directory holds the reverse-proxy deployment pattern for the public verifier.

## Important

The application itself remains loopback-safe by default and requires the explicit `--public` opt-in before binding outside localhost. The public exposure should happen only behind TLS termination and after the release gate in `docs/THREAT-MODEL.md` is satisfied.

## Example setup

1. Place your certificate and key in `deploy/certs/fullchain.pem` and `deploy/certs/privkey.pem`.
2. Start the stack:

```bash
docker compose up --build -d
```

3. Confirm the verifier is reachable through the proxy.

This scaffold intentionally keeps the app behind nginx for production deployment while preserving the repo's safety model.
