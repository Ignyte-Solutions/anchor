# CONFORMANCE

## Goal

Ensure equivalent verification outcomes across implementations.

## Required tests

- Canonical JSON determinism
- Capability signature valid/invalid vectors
- Action signature valid/invalid vectors
- Audience mismatch rejection
- Replay detection behavior
- Replay TTL/window behavior
- Delegation depth enforcement
- Challenge-mode enforcement for high-risk action classes
- Policy-hash integrity checks
- Trust-bundle key-validity window checks
- Trust-bundle revocation path handling
- Reason code consistency

## Advanced multi-system scenario suite

The conformance harness includes realistic end-to-end system emulations beyond basic vectors:
- Cloud infrastructure (`aws:*`)
- Social publishing (`social:*`)
- Banking transfers (`bank:*`)
- Support ticketing (`support:*`)
- Payout operations (`payments:*`)
- Healthcare EHR updates (`healthcare:*`)
- Logistics shipment creation (`logistics:*`)

Scenarios include replay attempts, content-moderation policies, sanctions checks, insufficient-funds rejection, and high-risk challenge requirements.

## Pass criteria

A conformant implementation must match expected `decision` and `reason_codes` for all official vectors.

Language SDK offline verifiers must preserve reason-code ordering and replay status semantics defined by the Go reference engine.
