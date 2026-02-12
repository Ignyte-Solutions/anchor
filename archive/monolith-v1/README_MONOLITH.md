# Ignyte Anchor

Ignyte Anchor is a cryptographically verifiable delegated-authority system for autonomous agents.

This implementation includes:
- Capability issuance (issuer signs delegated authority)
- Agent action envelope signing
- Deterministic action verification
- Append-only hash-chained audit logging
- API server for capability issuance and action verification
- SDK clients for Go/TypeScript/Python/Java
- Unit and integration tests (including delegated authority against a fake AWS-like service)

## Repository structure

- `cmd/ignyte-anchor`: API server entrypoint
- `internal/domain`: core data models and validation
- `internal/crypto`: Ed25519 and identity helpers
- `internal/capability`: capability ID/signing/verification logic
- `internal/action`: action ID/signing/verification logic
- `internal/issuer`: capability issuer service
- `internal/runtime`: agent runtime for signed action envelopes
- `internal/verifier`: deterministic stateless verification engine
- `internal/audit`: append-only hash-chained audit log
- `internal/api`: HTTP handlers, config, and server wiring
- `openapi/ignyte-anchor.yaml`: API schema
- `sdk/go`, `sdk/typescript`, `sdk/python`, `sdk/java`: client SDKs
- `tests/integration`: integration tests
- `FRONTEND.md`: frontend integration guidance
- `DEVELOPER.md`: endpoint and SDK developer docs

## Required server environment variables

- `IGNYTE_ANCHOR_SERVER_ADDR`
- `IGNYTE_ANCHOR_API_BASE_URL`
- `IGNYTE_ANCHOR_AUDIT_LOG_PATH`
- `IGNYTE_ANCHOR_ALLOWED_ORIGINS`
- `IGNYTE_ANCHOR_ISSUER_PRIVATE_KEY_B64`

## Local run

1. Copy `.env.example` values into your environment and set a real private key.
2. Generate an Ed25519 keypair and export the Base64 private key.
3. Create the audit log directory if it does not exist (for example `mkdir -p ./data`).
4. Set required environment variables.
5. Run:

```bash
go run ./cmd/ignyte-anchor
```

## Test

```bash
go test ./...
```

## API quick check

```bash
curl -sS "$IGNYTE_ANCHOR_API_BASE_URL/healthz"
```
