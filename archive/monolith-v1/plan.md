Name: Ignyte Anchor (Always reference it as Ignyte Anchor not just "anchor")
Programming Language: Go for Core, sdks or whatever should be written for TS/Python/Go/etc
Company: Ignyte Solutions
You may use api.ignyteanchor.com as the api to use in prod (obviously for dev you wil use localhost). Build in api support for the frontend and write (and activley update) FRONTEND.md for how to implement it but dont make a frontend yet. Make unit tests and actual tests that test authority. For example, you could build a fake AWS-like service to test delegated access. You'll need mutliple things.

Make sure this codebase is modular and maintainable. Like dont write massivley long files, make sure to spread it out.

Use Go programming best practices. 

Do NOT hardcode things into the code. Please. Use configs or env vars. Do NOT use fallback logic. Anything that will break in prod don't do. Don't leave any TODOs. 


# SYSTEM OVERVIEW

## Problem Statement

Modern autonomous software systems (agents, automation pipelines, orchestration services) perform actions on behalf of users or organizations. Current authorization models rely on:

* static credentials (API keys)
* broad permissions
* implicit trust
* non-verifiable audit trails

These approaches fail under autonomous execution because:

1. Authority is not bounded or portable.
2. Actions cannot be independently verified.
3. Delegation chains are implicit.
4. Revocation is coarse and unreliable.
5. External systems cannot reason about authorization decisions.

The system defined here introduces:

* explicit delegation of authority
* cryptographically verifiable authorization
* portable proof of authority
* deterministic action verification

without requiring changes from external services.

---

# HIGH-LEVEL DESIGN GOALS

The system must satisfy:

### Functional goals

* Allow autonomous agents to execute actions safely.
* Restrict authority using explicit capabilities.
* Provide deterministic auditability.
* Allow independent verification of actions.

### Architectural goals

* Phase I usable entirely internally.
* Phase II compatible without redesign.
* No external coordination required.
* Verification must not depend on centralized services.

### Security goals

* Authorization must be explicit and bounded.
* Authority must be cryptographically provable.
* Actions must be tamper-evident.
* Revocation must be supported without global state.

---

# SYSTEM MODEL

The system consists of four conceptual entities:

```
Issuer → Agent → Capability → Action
```

### Issuer

An entity that grants authority.

Examples:

* organization
* user
* service account

Issuer owns a cryptographic identity.

---

### Agent

An autonomous executor.

Properties:

* performs actions
* holds capabilities
* signs execution results

Agents do not inherently possess authority.

Authority is always delegated.

---

### Capability

A signed declaration of permitted authority.

Defines:

* what actions are allowed
* constraints on execution
* temporal bounds

Capabilities are portable and verifiable.

---

### Action

An executed operation performed by an agent.

Every action must reference a capability and be signed.

---

# CRYPTOGRAPHIC FOUNDATIONS

## Identity Primitive

Each issuer possesses:

```
Ed25519 keypair (recommended)
```

Reasons:

* small signatures
* fast verification
* widely supported
* deterministic

Issuer identity is defined as:

```
issuer_id = hash(public_key)
```

No centralized identity registry exists.

---

## Signing Model

Three signatures exist:

1. Capability signature (issuer → agent)
2. Action signature (agent → action)
3. Optional audit chain signature (system integrity)

Verification requires only public keys.

---

# DATA STRUCTURES

## 1. Issuer Descriptor

```
Issuer {
    issuer_id: bytes32
    public_key: bytes
    metadata: optional
}
```

Metadata may include:

* organization name
* contact information
* certificate binding (future)

Not required for verification.

---

## 2. Agent Descriptor

```
Agent {
    agent_id: bytes32
    public_key: bytes
    issuer_id: bytes32
}
```

Agents may be ephemeral.

Agent identity does not imply authority.

---

## 3. Capability Token (Core Object)

Capability defines authority.

```
Capability {
    version: int
    capability_id: bytes32

    issuer_id: bytes32
    agent_id: bytes32

    allowed_actions: [ActionType]
    constraints: {
        resource_limits,
        spend_limits,
        api_scopes,
        rate_limits,
        environment_constraints
    }

    issued_at: timestamp
    expires_at: timestamp
    nonce: bytes

    signature: bytes
}
```

Important rules:

* Capability must be immutable.
* Constraints must be machine-verifiable.
* Capability must be self-contained.

No external lookup required.

---

## 4. Action Envelope

Every action is wrapped in:

```
ActionEnvelope {
    action_id: bytes32
    agent_id: bytes32
    capability_id: bytes32

    action_type: string
    action_payload: bytes

    timestamp: timestamp

    agent_signature: bytes
}
```

---

# VERIFICATION MODEL

Verification algorithm:

```
1. Verify issuer signature on capability.
2. Verify capability validity window.
3. Verify agent matches capability.
4. Verify agent signature on action.
5. Verify action within capability scope.
6. Verify constraints satisfied.
```

Result:

```
AUTHORIZED | REJECTED
```

No network calls required.

---

# PHASE I IMPLEMENTATION

## Objective

Internal safe autonomous execution.

### Components

1. Capability Issuer Service
2. Agent Runtime
3. Verification Engine
4. Audit Log System

---

## Capability Issuer Service

Responsibilities:

* generate capabilities
* sign capabilities
* enforce delegation policies

API example:

```
POST /capabilities
{
    agent_id,
    allowed_actions,
    constraints,
    expiration
}
```

Returns signed capability.

---

## Agent Runtime

Responsibilities:

* request capabilities
* execute actions
* sign action envelopes
* attach capability references

Agent never receives raw credentials.

---

## Verification Engine

Library component.

Functions:

```
verifyCapability(capability)
verifyAction(actionEnvelope)
```

Must be deterministic and stateless.

---

## Audit Log

Append-only log:

```
[Capability Issued]
[Action Executed]
[Verification Result]
```

Log integrity optionally protected via hash chaining.

---

# PHASE II EXTENSION (BUILT IN FROM START)

Phase II introduces **portable verification**, not networking.

Changes:

* Capability tokens become externally shareable.
* Action envelopes become independently verifiable artifacts.

No protocol negotiation introduced.

---

## External Verification Flow

```
External System receives:
    ActionEnvelope + Capability

External System runs:
    verifyAction()
```

If valid:

* authority proven
* issuer proven
* scope proven

External system need not trust issuer operationally.

Only cryptographically.

---

# REVOCATION MODEL

Revocation must avoid centralized dependency.

Two mechanisms:

### 1. Short-lived capabilities (preferred)

Capabilities expire quickly.

Reduces revocation complexity.

### 2. Revocation lists (optional)

Issuer publishes revoked capability IDs.

Verification optionally checks list.

Not required for Phase II.

---

# SECURITY PROPERTIES

System guarantees:

* Explicit delegation
* Non-repudiation
* Tamper-evident execution
* Bounded authority
* Offline verification

System intentionally does NOT guarantee:

* global identity trust
* issuer reputation
* discovery mechanisms

Those belong to later phases.

---

# WHAT IS DELIBERATELY EXCLUDED

Do NOT include:

* agent discovery protocols
* reputation scoring
* identity federation
* global registries
* negotiation frameworks

These introduce coordination problems prematurely.

---

# IMPLEMENTATION STACK RECOMMENDATION

Core library:

* Rust or Go (verification engine)
* deterministic execution

SDK layers:

* TypeScript
* Python

Storage:

* append-only event store
* immutable logs preferred

Cryptography:

* Ed25519
* SHA-256 hashing

---

# SUCCESS CRITERIA

Phase I + II is successful when:

1. Autonomous agents can operate without raw credentials.
2. Every action is independently verifiable.
3. Authorization decisions can be proven externally.
4. Verification works without contacting issuer infrastructure.

At this point the system becomes capable of evolving into inter-organizational trust infrastructure without redesign.

---

# FINAL NOTE

The key architectural constraint throughout:

> Authority must be portable, but trust must remain local.

This separation prevents premature coupling and allows the system to evolve naturally into broader infrastructure if adoption occurs.

---

If you want next, I can write the **Phase II.5 evolution plan** — the exact minimal changes required when external systems begin actively verifying capabilities, which is where most identity systems accidentally break compatibility.
