package main

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	anchorcrypto "github.com/ignyte-solutions/ignyte-anchor-protocol/core/crypto"
	"github.com/ignyte-solutions/ignyte-anchor-protocol/core/v2"
)

func main() {
	referenceTime := time.Date(2026, 2, 16, 15, 4, 5, 0, time.UTC)

	issuerPub, issuerPriv, err := anchorcrypto.GenerateEd25519KeyPair()
	must("generate issuer keypair", err)
	agentPub, agentPriv, err := anchorcrypto.GenerateEd25519KeyPair()
	must("generate agent keypair", err)
	registryPub, registryPriv, err := anchorcrypto.GenerateEd25519KeyPair()
	must("generate registry signer keypair", err)

	issuerID, err := anchorcrypto.DeriveIDFromPublicKey(issuerPub)
	must("derive issuer id", err)
	agentID, err := anchorcrypto.DeriveIDFromPublicKey(agentPub)
	must("derive agent id", err)

	capability := v2.Capability{
		Version:      v2.Version,
		IssuerID:     issuerID,
		IssuerKID:    "issuer-k1",
		AgentID:      agentID,
		Audience:     "payments-api",
		PolicyHash:   "sha256:payments-policy-v1",
		IssuedAt:     referenceTime.Add(-5 * time.Minute),
		ExpiresAt:    referenceTime.Add(55 * time.Minute),
		Nonce:        "cap-2026-02-16-001",
		AllowedActions: []string{
			"payments.transfer.create",
			"payments.refund.create",
		},
		Constraints: v2.ConstraintSet{
			ResourceLimits:         map[string]int64{"tokens": 5000},
			SpendLimits:            map[string]int64{"usd_cents": 200000},
			APIScopes:              []string{"payments:write"},
			RateLimits:             map[string]int64{"per_minute": 120},
			EnvironmentConstraints: []string{"prod"},
		},
		Delegation: v2.Delegation{
			Depth:    0,
			MaxDepth: 1,
		},
		TransparencyRef: "trn:example:capabilities:2026-02-16",
	}
	must("sign capability", v2.SignCapability(&capability, issuerPriv))

	allowAction := v2.ActionEnvelope{
		AgentID:      agentID,
		CapabilityID: capability.CapabilityID,
		Audience:     "payments-api",
		ActionType:   "payments.transfer.create",
		ActionPayload: json.RawMessage(
			`{"amount_cents":2500,"currency":"USD","destination_account":"acct_demo_001"}`,
		),
		ConstraintEvidence: v2.ConstraintEvidence{
			ResourceUsage: map[string]int64{"tokens": 900},
			SpendUsage:    map[string]int64{"usd_cents": 2500},
			RateUsage:     map[string]int64{"per_minute": 20},
			Environment:   "prod",
			APIScope:      "payments:write",
		},
		Timestamp: referenceTime,
	}
	must("sign allow action", v2.SignAction(&allowAction, agentPriv))

	trustBundle := v2.TrustBundle{
		BundleID:           "bundle-2026-02-16",
		IssuedAt:           referenceTime.Add(-10 * time.Minute),
		ExpiresAt:          referenceTime.Add(24 * time.Hour),
		SignerPublicKeyKID: "registry-signer-k1",
		Issuers: []v2.TrustBundleIssuer{
			{
				IssuerID:      issuerID,
				IssuerKID:     "issuer-k1",
				PublicKey:     anchorcrypto.PublicKeyToBase64(issuerPub),
				ValidFrom:     referenceTime.Add(-2 * time.Hour),
				ValidUntil:    referenceTime.Add(24 * time.Hour),
				AssuranceTier: "ORG_VERIFIED",
			},
		},
		RevocationPointers: []string{"https://registry.example/revocations/latest"},
	}
	must("sign trust bundle", v2.SignTrustBundle(&trustBundle, registryPriv))

	resolvedBundle, usedFallback, err := v2.ResolveTrustBundleWithFallback(
		staticTrustBundleFetcher{bundle: trustBundle},
		v2.NewInMemoryTrustBundleCache(),
		registryPub,
		referenceTime,
	)
	must("resolve trust bundle", err)

	fmt.Printf("bundle_source=fetched used_fallback=%t bundle_id=%s\n", usedFallback, resolvedBundle.BundleID)

	engine := v2.NewEngine()
	replayCache := v2.NewInMemoryWindowReplayCache()
	keyResolver := v2.TrustBundleKeyResolver{Bundle: resolvedBundle}

	baseReq := v2.VerifyRequest{
		Capability:         capability,
		Action:             allowAction,
		AgentPublicKey:     agentPub,
		ReferenceTime:      referenceTime,
		ExpectedAudience:   "payments-api",
		ExpectedPolicyHash: "sha256:payments-policy-v1",
		KeyResolver:        keyResolver,
		ReplayCache:        replayCache,
		ReplayWindow:       5 * time.Minute,
		ChallengePolicy: v2.StaticChallengePolicy{
			Required: map[string]struct{}{
				"payments.refund.create": {},
			},
		},
	}

	printResult("allow_transfer", engine.Verify(baseReq))
	printResult("replay_transfer", engine.Verify(baseReq))

	audienceMismatch := allowAction
	audienceMismatch.ActionID = ""
	audienceMismatch.AgentSignature = ""
	audienceMismatch.Audience = "admin-api"
	audienceMismatch.Timestamp = referenceTime.Add(1 * time.Minute)
	must("sign audience mismatch action", v2.SignAction(&audienceMismatch, agentPriv))
	audienceReq := baseReq
	audienceReq.Action = audienceMismatch
	printResult("audience_mismatch", engine.Verify(audienceReq))

	missingChallenge := allowAction
	missingChallenge.ActionID = ""
	missingChallenge.AgentSignature = ""
	missingChallenge.ActionType = "payments.refund.create"
	missingChallenge.Timestamp = referenceTime.Add(2 * time.Minute)
	must("sign high risk action", v2.SignAction(&missingChallenge, agentPriv))
	challengeReq := baseReq
	challengeReq.Action = missingChallenge
	printResult("challenge_required", engine.Verify(challengeReq))
}

type staticTrustBundleFetcher struct {
	bundle v2.TrustBundle
}

func (f staticTrustBundleFetcher) FetchLatest() (v2.TrustBundle, error) {
	return f.bundle, nil
}

func printResult(name string, result v2.VerificationResult) {
	payload, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		log.Fatalf("marshal result %s: %v", name, err)
	}
	fmt.Printf("scenario=%s\n%s\n", name, string(payload))
}

func must(op string, err error) {
	if err != nil {
		log.Fatalf("%s: %v", op, err)
	}
}
