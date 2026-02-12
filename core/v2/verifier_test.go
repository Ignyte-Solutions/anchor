package v2_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"

	anchorcrypto "github.com/ignyte-solutions/ignyte-anchor-protocol/core/crypto"
	"github.com/ignyte-solutions/ignyte-anchor-protocol/core/v2"
)

func TestVerifyAuthorizedWithAudienceAndPolicyHash(t *testing.T) {
	fixture := buildFixture(t, fixtureInput{})
	engine := v2.NewEngine()

	result := engine.Verify(v2.VerifyRequest{
		Capability:         fixture.capability,
		Action:             fixture.action,
		AgentPublicKey:     fixture.agentPublicKey,
		ReferenceTime:      fixture.referenceTime,
		ExpectedAudience:   "aws:prod:s3",
		ExpectedPolicyHash: fixture.capability.PolicyHash,
		KeyResolver:        fixture.keyResolver,
		ReplayCache:        v2.NewInMemoryReplayCache(),
		ChallengePolicy: v2.StaticChallengePolicy{Required: map[string]struct{}{
			"s3:DeleteObject": {},
		}},
	})

	if result.Decision != v2.DecisionAuthorized {
		t.Fatalf("expected AUTHORIZED, got %s with reasons %+v", result.Decision, result.Reasons)
	}
	if result.ReplayStatus != v2.ReplayStatusFresh {
		t.Fatalf("expected replay_status fresh, got %s", result.ReplayStatus)
	}
}

func TestVerifyRejectsAudienceMismatch(t *testing.T) {
	fixture := buildFixture(t, fixtureInput{audience: "aws:prod:s3"})
	fixture.action.Audience = "aws:prod:lambda"
	engine := v2.NewEngine()
	result := engine.Verify(v2.VerifyRequest{
		Capability:       fixture.capability,
		Action:           fixture.action,
		AgentPublicKey:   fixture.agentPublicKey,
		ReferenceTime:    fixture.referenceTime,
		ExpectedAudience: "aws:prod:s3",
		KeyResolver:      fixture.keyResolver,
	})
	if result.Decision != v2.DecisionRejected {
		t.Fatalf("expected REJECTED, got %s", result.Decision)
	}
	if !containsReasonCode(result.ReasonCodes, v2.ReasonCodeAudienceMismatch) {
		t.Fatalf("expected audience mismatch reason code, got %+v", result.ReasonCodes)
	}
}

func TestVerifyRejectsReplay(t *testing.T) {
	fixture := buildFixture(t, fixtureInput{})
	engine := v2.NewEngine()
	replayCache := v2.NewInMemoryReplayCache()
	first := engine.Verify(v2.VerifyRequest{
		Capability:     fixture.capability,
		Action:         fixture.action,
		AgentPublicKey: fixture.agentPublicKey,
		ReferenceTime:  fixture.referenceTime,
		KeyResolver:    fixture.keyResolver,
		ReplayCache:    replayCache,
	})
	if first.Decision != v2.DecisionAuthorized {
		t.Fatalf("first verify should authorize, got %s", first.Decision)
	}
	second := engine.Verify(v2.VerifyRequest{
		Capability:     fixture.capability,
		Action:         fixture.action,
		AgentPublicKey: fixture.agentPublicKey,
		ReferenceTime:  fixture.referenceTime,
		KeyResolver:    fixture.keyResolver,
		ReplayCache:    replayCache,
	})
	if second.Decision != v2.DecisionRejected {
		t.Fatalf("second verify should reject replay, got %s", second.Decision)
	}
	if second.ReplayStatus != v2.ReplayStatusReplay {
		t.Fatalf("expected replay status replay, got %s", second.ReplayStatus)
	}
	if !containsReasonCode(second.ReasonCodes, v2.ReasonCodeReplayDetected) {
		t.Fatalf("expected replay reason code, got %+v", second.ReasonCodes)
	}
}

func TestVerifyRejectsMissingChallengeForHighRiskAction(t *testing.T) {
	fixture := buildFixture(t, fixtureInput{actionType: "s3:DeleteObject", challengeNonce: ""})
	engine := v2.NewEngine()
	result := engine.Verify(v2.VerifyRequest{
		Capability:     fixture.capability,
		Action:         fixture.action,
		AgentPublicKey: fixture.agentPublicKey,
		ReferenceTime:  fixture.referenceTime,
		KeyResolver:    fixture.keyResolver,
		ChallengePolicy: v2.StaticChallengePolicy{Required: map[string]struct{}{
			"s3:DeleteObject": {},
		}},
	})
	if result.Decision != v2.DecisionRejected {
		t.Fatalf("expected REJECTED, got %s", result.Decision)
	}
	if !containsReasonCode(result.ReasonCodes, v2.ReasonCodeChallengeRequired) {
		t.Fatalf("expected challenge required reason code, got %+v", result.ReasonCodes)
	}
}

func TestVerifyRejectsTransparencyInvalid(t *testing.T) {
	fixture := buildFixture(t, fixtureInput{})
	engine := v2.NewEngine()
	result := engine.Verify(v2.VerifyRequest{
		Capability:     fixture.capability,
		Action:         fixture.action,
		AgentPublicKey: fixture.agentPublicKey,
		ReferenceTime:  fixture.referenceTime,
		KeyResolver:    fixture.keyResolver,
		Transparency: v2.FuncTransparencyVerifier(func(_, _ string) error {
			return errors.New("missing transparency proof")
		}),
	})
	if result.Decision != v2.DecisionRejected {
		t.Fatalf("expected REJECTED, got %s", result.Decision)
	}
	if !containsReasonCode(result.ReasonCodes, v2.ReasonCodeTransparencyInvalid) {
		t.Fatalf("expected transparency invalid reason code, got %+v", result.ReasonCodes)
	}
}

func TestVerifyRejectsPolicyHookViolation(t *testing.T) {
	fixture := buildFixture(t, fixtureInput{})
	engine := v2.NewEngine()
	result := engine.Verify(v2.VerifyRequest{
		Capability:     fixture.capability,
		Action:         fixture.action,
		AgentPublicKey: fixture.agentPublicKey,
		ReferenceTime:  fixture.referenceTime,
		KeyResolver:    fixture.keyResolver,
		PolicyEvaluator: v2.FuncPolicyEvaluator(func(_ v2.Capability, _ v2.ActionEnvelope) ([]v2.ReasonCode, []string) {
			return []v2.ReasonCode{v2.ReasonCodePolicyHookRejected}, []string{"approval workflow required"}
		}),
	})
	if result.Decision != v2.DecisionRejected {
		t.Fatalf("expected REJECTED, got %s", result.Decision)
	}
	if !containsReasonCode(result.ReasonCodes, v2.ReasonCodePolicyHookRejected) {
		t.Fatalf("expected policy hook reason code, got %+v", result.ReasonCodes)
	}
}

func TestVerifyRejectsIssuerKeyOutsideValidityWindow(t *testing.T) {
	fixture := buildFixture(t, fixtureInput{})
	resolver := fixture.keyResolver.(v2.TrustBundleKeyResolver)
	resolver.Bundle.Issuers[0].ValidUntil = fixture.referenceTime.Add(-1 * time.Minute)
	fixture.keyResolver = resolver

	engine := v2.NewEngine()
	result := engine.Verify(v2.VerifyRequest{
		Capability:     fixture.capability,
		Action:         fixture.action,
		AgentPublicKey: fixture.agentPublicKey,
		ReferenceTime:  fixture.referenceTime,
		KeyResolver:    fixture.keyResolver,
	})
	if result.Decision != v2.DecisionRejected {
		t.Fatalf("expected REJECTED, got %s", result.Decision)
	}
	if !containsReasonCode(result.ReasonCodes, v2.ReasonCodeIssuerKeyOutOfWindow) {
		t.Fatalf("expected issuer key out-of-window reason code, got %+v", result.ReasonCodes)
	}
}

func TestVerifyWindowedReplayCacheAllowsReuseAfterWindow(t *testing.T) {
	fixture := buildFixture(t, fixtureInput{})
	engine := v2.NewEngine()
	cache := v2.NewInMemoryWindowReplayCache()

	first := engine.Verify(v2.VerifyRequest{
		Capability:     fixture.capability,
		Action:         fixture.action,
		AgentPublicKey: fixture.agentPublicKey,
		ReferenceTime:  fixture.referenceTime,
		KeyResolver:    fixture.keyResolver,
		ReplayCache:    cache,
		ReplayWindow:   1 * time.Minute,
	})
	if first.Decision != v2.DecisionAuthorized {
		t.Fatalf("first verify should authorize, got %s", first.Decision)
	}

	second := engine.Verify(v2.VerifyRequest{
		Capability:     fixture.capability,
		Action:         fixture.action,
		AgentPublicKey: fixture.agentPublicKey,
		ReferenceTime:  fixture.referenceTime.Add(10 * time.Minute),
		KeyResolver:    fixture.keyResolver,
		ReplayCache:    cache,
		ReplayWindow:   1 * time.Minute,
	})
	if second.Decision != v2.DecisionAuthorized {
		t.Fatalf("expected second verify to authorize after replay window, got %s with reasons %+v", second.Decision, second.Reasons)
	}
	if second.ReplayStatus != v2.ReplayStatusFresh {
		t.Fatalf("expected replay_status fresh, got %s", second.ReplayStatus)
	}
}

type fixtureInput struct {
	audience       string
	actionType     string
	challengeNonce string
}

type verifyFixture struct {
	capability     v2.Capability
	action         v2.ActionEnvelope
	agentPublicKey []byte
	referenceTime  time.Time
	keyResolver    v2.IssuerKeyResolver
}

func buildFixture(t *testing.T, input fixtureInput) verifyFixture {
	t.Helper()
	if input.audience == "" {
		input.audience = "aws:prod:s3"
	}
	if input.actionType == "" {
		input.actionType = "s3:PutObject"
	}
	if input.challengeNonce == "" && input.actionType != "s3:DeleteObject" {
		input.challengeNonce = "nonce-123"
	}
	issuerPublicKey, issuerPrivateKey, err := anchorcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate issuer key pair: %v", err)
	}
	agentPublicKey, agentPrivateKey, err := anchorcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate agent key pair: %v", err)
	}
	issuerID, err := anchorcrypto.DeriveIDFromPublicKey(issuerPublicKey)
	if err != nil {
		t.Fatalf("derive issuer id: %v", err)
	}
	agentID, err := anchorcrypto.DeriveIDFromPublicKey(agentPublicKey)
	if err != nil {
		t.Fatalf("derive agent id: %v", err)
	}
	issuedAt := time.Date(2026, 2, 13, 5, 0, 0, 0, time.UTC)
	capability := v2.Capability{
		Version:        v2.Version,
		IssuerID:       issuerID,
		IssuerKID:      "k1",
		AgentID:        agentID,
		Audience:       input.audience,
		AllowedActions: []string{"s3:DeleteObject", "s3:PutObject"},
		Constraints: v2.ConstraintSet{
			ResourceLimits:         map[string]int64{"s3:objects": 2},
			SpendLimits:            map[string]int64{"usd_cents": 100},
			APIScopes:              []string{"aws:s3"},
			RateLimits:             map[string]int64{"requests_per_minute": 10},
			EnvironmentConstraints: []string{"prod"},
		},
		Delegation:      v2.Delegation{Depth: 0, MaxDepth: 1},
		PolicyHash:      "policy-hash-v2",
		TransparencyRef: "tr-log://entry-1",
		IssuedAt:        issuedAt,
		ExpiresAt:       issuedAt.Add(15 * time.Minute),
		Nonce:           "nonce-capability",
	}
	if err := v2.SignCapability(&capability, issuerPrivateKey); err != nil {
		t.Fatalf("sign capability: %v", err)
	}
	action := v2.ActionEnvelope{
		AgentID:      agentID,
		CapabilityID: capability.CapabilityID,
		Audience:     input.audience,
		ActionType:   input.actionType,
		ActionPayload: json.RawMessage(`{
			"bucket":"my-bucket",
			"key":"hello.txt"
		}`),
		ConstraintEvidence: v2.ConstraintEvidence{
			ResourceUsage: map[string]int64{"s3:objects": 1},
			SpendUsage:    map[string]int64{"usd_cents": 10},
			RateUsage:     map[string]int64{"requests_per_minute": 1},
			Environment:   "prod",
			APIScope:      "aws:s3",
		},
		ChallengeNonce: input.challengeNonce,
		Timestamp:      issuedAt.Add(2 * time.Minute),
	}
	if err := v2.SignAction(&action, agentPrivateKey); err != nil {
		t.Fatalf("sign action: %v", err)
	}
	bundle := v2.TrustBundle{
		BundleID:           "bundle-1",
		IssuedAt:           issuedAt,
		ExpiresAt:          issuedAt.Add(24 * time.Hour),
		Signature:          "placeholder",
		SignerPublicKeyKID: "bundle-signer",
		Issuers: []v2.TrustBundleIssuer{
			{
				IssuerID:      issuerID,
				IssuerKID:     "k1",
				PublicKey:     anchorcrypto.PublicKeyToBase64(issuerPublicKey),
				ValidFrom:     issuedAt.Add(-1 * time.Hour),
				ValidUntil:    issuedAt.Add(24 * time.Hour),
				AssuranceTier: "ORG_VERIFIED",
			},
		},
	}
	return verifyFixture{
		capability:     capability,
		action:         action,
		agentPublicKey: bytes.Clone(agentPublicKey),
		referenceTime:  action.Timestamp,
		keyResolver:    v2.TrustBundleKeyResolver{Bundle: bundle},
	}
}

func containsReasonCode(codes []v2.ReasonCode, target v2.ReasonCode) bool {
	for _, code := range codes {
		if code == target {
			return true
		}
	}
	return false
}
