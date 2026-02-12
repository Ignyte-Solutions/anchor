# SPEC

## Objective

Define open, deterministic authorization artifacts that can be verified locally.

## Normative objects

- `CapabilityV2`
- `ActionEnvelopeV2`
- `VerificationResultV2`
- `TrustBundle`

## Verification function

`verify(capability, action, trust_bundle, local_policy, replay_cache, now) -> VerificationResultV2`

Verification MUST NOT require network calls.

## Mandatory checks

1. Capability signature verification.
2. Action signature verification.
3. Issuer key resolution (`issuer_id` + `issuer_kid`) from local trust material.
4. Capability validity window (`issued_at`, `expires_at`).
5. Audience equality checks.
6. Delegation depth bounded by `max_depth`.
7. Allowed action scope.
8. Constraint evidence checks.
9. Replay checks.
10. Policy hash checks when expected policy is configured.

## Output requirements

- `decision` must be deterministic.
- `reason_codes` must contain stable machine-readable values.
- `reasons` must be human-readable and non-empty for rejected decisions.
