# Ignyte Anchor Developer Docs

This document is for backend/frontend engineers integrating with Ignyte Anchor.

## Product summary

Ignyte Anchor provides explicit delegated authority for autonomous systems.

- Issuer signs capability tokens for agents.
- Agent signs action envelopes.
- Verifier deterministically returns `AUTHORIZED` or `REJECTED`.
- Audit events are append-only and hash chained.

## Current API surface

- `GET /healthz`
- `POST /v1/capabilities`
- `POST /v1/actions/verify`

OpenAPI spec:
- `openapi/ignyte-anchor.yaml`

## Endpoint examples

## 1. Health

```bash
curl -sS http://localhost:8080/healthz
```

Expected response:

```json
{
  "status": "ok",
  "name": "Ignyte Anchor",
  "api": "http://localhost:8080"
}
```

## 2. Issue capability

```bash
curl -sS -X POST http://localhost:8080/v1/capabilities \
  -H 'Content-Type: application/json' \
  -d '{
    "agent_public_key": "BASE64_ED25519_PUBLIC_KEY",
    "allowed_actions": ["s3:PutObject", "lambda:InvokeFunction"],
    "constraints": {
      "resource_limits": {"s3:objects": 10, "lambda:invocations": 20},
      "spend_limits": {"usd_cents": 5000},
      "api_scopes": ["aws:s3", "aws:lambda"],
      "rate_limits": {"requests_per_minute": 60},
      "environment_constraints": ["prod"]
    },
    "expires_at": "2026-02-13T12:00:00Z"
  }'
```

Success response returns a signed `capability` and `issuer` identity.

## 3. Verify action

```bash
curl -sS -X POST http://localhost:8080/v1/actions/verify \
  -H 'Content-Type: application/json' \
  -d '{
    "capability": {"...":"signed capability object"},
    "action": {"...":"signed action envelope"},
    "issuer_public_key": "BASE64_ED25519_PUBLIC_KEY",
    "agent_public_key": "BASE64_ED25519_PUBLIC_KEY",
    "revoked_capability_ids": []
  }'
```

Verification response:

```json
{
  "decision": "AUTHORIZED",
  "reasons": []
}
```

or

```json
{
  "decision": "REJECTED",
  "reasons": [
    "action_type is not allowed by capability",
    "api_scope is not allowed by capability constraints"
  ]
}
```

## Verification semantics

Verifier checks (in effect):

1. Capability signature validity
2. Capability time window validity
3. Agent identity consistency
4. Action signature validity
5. Action scope against `allowed_actions`
6. Constraint evidence against capability constraints
7. Optional revocation-list rejection

## SDK matrix

Implemented SDK clients:

- TypeScript: `sdk/typescript/client.ts`
- Go: `sdk/go/client.go`
- Python: `sdk/python/client.py`
- Java: `sdk/java/IgnyteAnchorClient.java`

Java notes:
- Uses `java.net.http.HttpClient`.
- Methods accept request JSON strings and return raw response JSON strings.
- Host app should use its own JSON library (Jackson/Gson/etc.) for object mapping.

## Dashboard engineering guidance

For UI architecture and page-level guidance:
- `FRONTEND.md`

Recommended dashboard modules:
- issuer context
- token issuance and inspection
- action verification
- audit timeline
- developer playground

## Server config (required env vars)

- `IGNYTE_ANCHOR_SERVER_ADDR`
- `IGNYTE_ANCHOR_API_BASE_URL`
- `IGNYTE_ANCHOR_AUDIT_LOG_PATH`
- `IGNYTE_ANCHOR_ALLOWED_ORIGINS`
- `IGNYTE_ANCHOR_ISSUER_PRIVATE_KEY_B64`

## Local commands

Run API:

```bash
go run ./cmd/ignyte-anchor
```

Run tests:

```bash
go test ./...
```

Run vet:

```bash
go vet ./...
```
