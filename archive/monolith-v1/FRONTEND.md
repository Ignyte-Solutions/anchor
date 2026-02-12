# Ignyte Anchor Frontend Guide

This document defines how to build a production-grade dashboard for Ignyte Anchor.

## Core model clarity

You called out an important distinction.

- End user (issuer operator): the human or team member who configures delegated authority.
- Issuer: the cryptographic identity (public/private key pair) that signs capabilities.
- Token (capability): the signed authority object issued to an agent.
- Agent: the autonomous executor identity that receives capabilities and signs actions.
- Action envelope: the signed operation artifact to verify.

The end user interacts with UI forms and workflows. The issuer identity and tokens are cryptographic artifacts behind those workflows.

## API base URLs

- Production: `https://api.ignyteanchor.com`
- Local: `http://localhost:8080`

Frontend must read base URL from env, never hardcode.

## Required frontend env vars

- `VITE_IGNYTE_ANCHOR_API_BASE_URL`

Example values:
- Local: `http://localhost:8080`
- Production: `https://api.ignyteanchor.com`

## API endpoints

Current backend endpoints are:

- `GET /healthz`
- `POST /v1/capabilities`
- `POST /v1/actions/verify`

Source of truth schema:
- `openapi/ignyte-anchor.yaml`

### `GET /healthz`

Use this for startup diagnostics and status banner.

Response shape:
- `status`: expected `ok`
- `name`: expected `Ignyte Anchor`
- `api`: configured base URL

### `POST /v1/capabilities`

Purpose: issuer creates a signed capability for an agent.

Request fields:
- `agent_public_key` (Base64 Ed25519 public key)
- `allowed_actions` (`string[]`)
- `constraints`:
  - `resource_limits` (`Record<string, int64>`)
  - `spend_limits` (`Record<string, int64>`)
  - `api_scopes` (`string[]`)
  - `rate_limits` (`Record<string, int64>`)
  - `environment_constraints` (`string[]`)
- `expires_at` (RFC3339 timestamp)
- `nonce` (optional, if omitted backend generates one)

Response fields:
- `capability` (full signed token)
- `issuer` (`issuer_id`, `public_key`)

### `POST /v1/actions/verify`

Purpose: determine whether a specific action envelope is authorized by a capability.

Request fields:
- `capability`
- `action`
- `issuer_public_key`
- `agent_public_key`
- `revoked_capability_ids` (`string[]`, pass `[]` if none)

Response fields:
- `decision`: `AUTHORIZED | REJECTED`
- `reasons`: list of rejection reasons (empty when authorized)

## Dashboard information architecture

For a serious dashboard, separate by intent, not just endpoint.

### 1. Issuers

Goal: manage issuer/operator context.

Views:
- Issuer identity card (`issuer_id`, public key fingerprint)
- Environment selector (`prod`, `staging`, etc.)
- Key policy panel (display-only if key management is external)

### 2. Capability Tokens

Goal: create and inspect capabilities.

Views:
- Capability issuance form
- Capability token detail viewer (raw + parsed)
- Token search/filter table by `agent_id`, `action`, `expires_at`
- Expiring-soon indicator

### 3. Action Verification

Goal: verify live or pasted action artifacts.

Views:
- Verification form (`capability + action + keys + revoked ids`)
- Decision panel with rejection reasons grouped by category:
  - signature/key mismatch
  - temporal invalidity
  - action scope mismatch
  - constraint violation
  - revocation

### 4. Audit Timeline

Goal: explain what happened in sequence.

Views:
- Timeline of issuance and verification events
- Hash-chain metadata view (`previous_hash`, `entry_hash`)
- Export button (JSON lines)

### 5. Developer Playground

Goal: test payloads quickly.

Views:
- Prebuilt request templates for each endpoint
- Copyable cURL snippets
- SDK snippets (TypeScript/Go/Python/Java)

## Required frontend features for v1 dashboard

- Strong form validation for all required fields
- JSON linting/editor for `action_payload`
- RFC3339 time picker + UTC display
- Token and action JSON pretty viewer
- Decision badge with reason list
- Safe copy buttons for token/action blobs
- Error boundary for malformed JSON and server failures

## Recommended UI state model

Use separate stores/slices:
- `issuerContext`
- `capabilityDraft`
- `issuedCapabilities`
- `verificationDraft`
- `verificationHistory`
- `healthStatus`

Do not couple capability issuance form state with verification form state.

## Validation rules to enforce in UI

- Never submit empty maps/arrays as `null`; send proper JSON values.
- Require non-empty `allowed_actions`.
- Require all constraints subfields.
- Require non-empty `revoked_capability_ids` entries (if provided).
- Ensure `expires_at` is after current UTC time.
- Require valid JSON for `action_payload`.

## Suggested navigation map

- `/dashboard/overview`
- `/dashboard/issuers`
- `/dashboard/capabilities`
- `/dashboard/verify`
- `/dashboard/audit`
- `/dashboard/playground`

## API integration examples (frontend)

TypeScript client location:
- `sdk/typescript/client.ts`

```ts
import { IgnyteAnchorClient } from "../sdk/typescript/client";

const apiBaseUrl = import.meta.env.VITE_IGNYTE_ANCHOR_API_BASE_URL;
if (!apiBaseUrl) {
  throw new Error("VITE_IGNYTE_ANCHOR_API_BASE_URL is required");
}

const client = new IgnyteAnchorClient(apiBaseUrl, fetch);
```

## CORS

Backend reads `IGNYTE_ANCHOR_ALLOWED_ORIGINS`.
The browser origin of your dashboard must be present there.

## Developer docs

For endpoint examples, request/response payloads, and SDK matrix:
- `DEVELOPER.md`
