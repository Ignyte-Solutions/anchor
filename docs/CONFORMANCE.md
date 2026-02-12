# CONFORMANCE

## Goal

Ensure equivalent verification outcomes across implementations.

## Required tests

- Canonical JSON determinism
- Capability signature valid/invalid vectors
- Action signature valid/invalid vectors
- Audience mismatch rejection
- Replay detection behavior
- Reason code consistency

## Pass criteria

A conformant implementation must match expected `decision` and `reason_codes` for all official vectors.
