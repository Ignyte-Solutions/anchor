# THREAT_MODEL

## In scope

- Forged capability signatures
- Forged action signatures
- Replay of valid action envelopes
- Cross-audience capability reuse
- Expired capability reuse
- Constraint escalation attempts

## Assumptions

- Issuer private keys are not exposed to untrusted runtimes.
- Verifier trust material is locally controlled.
- Replay cache availability is best-effort but recommended.

## Out of scope

- Global identity reputation
- Universal trust decisions
- Runtime compromise prevention on end-user devices

## Mitigations

- Ed25519 signatures
- Canonicalization for deterministic hashing
- Audience binding
- Delegation depth controls
- Trust bundle key pinning
- Reason-code observability
