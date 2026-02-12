# PROOF_SKETCH

Define deterministic verifier relation:

`R = Verify(C, A, T, P, N, t)` where

- `C`: capability
- `A`: action envelope
- `T`: trust material
- `P`: local policy
- `N`: replay state
- `t`: reference time

If all predicates hold, `R.decision = AUTHORIZED`; otherwise `REJECTED` with stable reason codes.

Core predicates:

- `SigCap(C, T)`
- `SigAct(A)`
- `Time(C, t)`
- `Bind(C, A)` (capability/action binding and audience)
- `Scope(C, A)`
- `Constraints(C, A)`
- `Replay(N, A.action_id)`
- `Policy(P, C.policy_hash, A)`
