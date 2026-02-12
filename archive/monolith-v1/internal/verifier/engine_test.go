package verifier_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	anchorcrypto "github.com/ignyte-solutions/ignyte-anchor/internal/crypto"
	"github.com/ignyte-solutions/ignyte-anchor/internal/domain"
	"github.com/ignyte-solutions/ignyte-anchor/internal/issuer"
	"github.com/ignyte-solutions/ignyte-anchor/internal/runtime"
	"github.com/ignyte-solutions/ignyte-anchor/internal/verifier"
)

type fixedClock struct {
	now time.Time
}

func (f fixedClock) Now() time.Time {
	return f.now
}

type verifyFixture struct {
	capability      domain.Capability
	action          domain.ActionEnvelope
	issuerPublicKey string
	agentPublicKey  string
}

func TestVerifyAuthorized(t *testing.T) {
	fixture := buildFixture(t)
	issuerPublicKey, err := anchorcrypto.PublicKeyFromBase64(fixture.issuerPublicKey)
	if err != nil {
		t.Fatalf("parse issuer public key: %v", err)
	}
	agentPublicKey, err := anchorcrypto.PublicKeyFromBase64(fixture.agentPublicKey)
	if err != nil {
		t.Fatalf("parse agent public key: %v", err)
	}
	engine := verifier.New()

	result := engine.Verify(verifier.VerifyRequest{
		Capability:      fixture.capability,
		Action:          fixture.action,
		IssuerPublicKey: issuerPublicKey,
		AgentPublicKey:  agentPublicKey,
		ReferenceTime:   fixture.action.Timestamp,
	})
	if result.Decision != domain.DecisionAuthorized {
		t.Fatalf("expected AUTHORIZED decision, got %s with reasons %v", result.Decision, result.Reasons)
	}
	if len(result.Reasons) != 0 {
		t.Fatalf("expected no rejection reasons for AUTHORIZED decision, got %v", result.Reasons)
	}
}

func TestVerifyRejectsActionOutsideCapabilityScope(t *testing.T) {
	fixture := buildFixture(t)
	issuerPublicKey, err := anchorcrypto.PublicKeyFromBase64(fixture.issuerPublicKey)
	if err != nil {
		t.Fatalf("parse issuer public key: %v", err)
	}
	agentPublicKey, err := anchorcrypto.PublicKeyFromBase64(fixture.agentPublicKey)
	if err != nil {
		t.Fatalf("parse agent public key: %v", err)
	}
	engine := verifier.New()
	fixture.action.ActionType = "ec2:TerminateInstances"

	result := engine.Verify(verifier.VerifyRequest{
		Capability:      fixture.capability,
		Action:          fixture.action,
		IssuerPublicKey: issuerPublicKey,
		AgentPublicKey:  agentPublicKey,
		ReferenceTime:   fixture.action.Timestamp,
	})
	if result.Decision != domain.DecisionRejected {
		t.Fatalf("expected REJECTED decision, got %s", result.Decision)
	}
	if !hasReason(result.Reasons, "action_type is not allowed by capability") {
		t.Fatalf("expected rejection reason for action scope, got %v", result.Reasons)
	}
}

func TestVerifyRejectsConstraintViolation(t *testing.T) {
	fixture := buildFixture(t)
	issuerPublicKey, err := anchorcrypto.PublicKeyFromBase64(fixture.issuerPublicKey)
	if err != nil {
		t.Fatalf("parse issuer public key: %v", err)
	}
	agentPublicKey, err := anchorcrypto.PublicKeyFromBase64(fixture.agentPublicKey)
	if err != nil {
		t.Fatalf("parse agent public key: %v", err)
	}
	engine := verifier.New()
	fixture.action.ConstraintEvidence.SpendUsage["usd_cents"] = 999

	result := engine.Verify(verifier.VerifyRequest{
		Capability:      fixture.capability,
		Action:          fixture.action,
		IssuerPublicKey: issuerPublicKey,
		AgentPublicKey:  agentPublicKey,
		ReferenceTime:   fixture.action.Timestamp,
	})
	if result.Decision != domain.DecisionRejected {
		t.Fatalf("expected REJECTED decision, got %s", result.Decision)
	}
	if !hasReason(result.Reasons, "spend usage for usd_cents exceeds limit") {
		t.Fatalf("expected rejection reason for spend limit, got %v", result.Reasons)
	}
}

func TestVerifyRejectsRevokedCapability(t *testing.T) {
	fixture := buildFixture(t)
	issuerPublicKey, err := anchorcrypto.PublicKeyFromBase64(fixture.issuerPublicKey)
	if err != nil {
		t.Fatalf("parse issuer public key: %v", err)
	}
	agentPublicKey, err := anchorcrypto.PublicKeyFromBase64(fixture.agentPublicKey)
	if err != nil {
		t.Fatalf("parse agent public key: %v", err)
	}
	engine := verifier.New()

	result := engine.Verify(verifier.VerifyRequest{
		Capability:      fixture.capability,
		Action:          fixture.action,
		IssuerPublicKey: issuerPublicKey,
		AgentPublicKey:  agentPublicKey,
		ReferenceTime:   fixture.action.Timestamp,
		RevocationList: verifier.StaticRevocationList{Revoked: map[string]struct{}{
			fixture.capability.CapabilityID: {},
		}},
	})
	if result.Decision != domain.DecisionRejected {
		t.Fatalf("expected REJECTED decision, got %s", result.Decision)
	}
	if !hasReason(result.Reasons, "capability is revoked") {
		t.Fatalf("expected rejection reason for revocation, got %v", result.Reasons)
	}
}

func buildFixture(t *testing.T) verifyFixture {
	t.Helper()
	issuerPublicKey, issuerPrivateKey, err := anchorcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate issuer key pair: %v", err)
	}
	agentPublicKey, agentPrivateKey, err := anchorcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate agent key pair: %v", err)
	}

	issuedAt := time.Date(2026, 2, 12, 17, 0, 0, 0, time.UTC)
	nonceSource := bytes.NewReader(bytes.Repeat([]byte{0x11}, 32))
	issuerService, err := issuer.NewService(issuerPrivateKey, nonceSource, fixedClock{now: issuedAt})
	if err != nil {
		t.Fatalf("create issuer service: %v", err)
	}
	capabilityToken, err := issuerService.IssueCapability(issuer.IssueCapabilityRequest{
		AgentPublicKey: anchorcrypto.PublicKeyToBase64(agentPublicKey),
		AllowedActions: []string{"s3:PutObject"},
		Constraints: domain.CapabilityConstraints{
			ResourceLimits:         map[string]int64{"s3:objects": 1},
			SpendLimits:            map[string]int64{"usd_cents": 100},
			APIScopes:              []string{"aws:s3"},
			RateLimits:             map[string]int64{"requests_per_minute": 10},
			EnvironmentConstraints: []string{"prod"},
		},
		ExpiresAt: issuedAt.Add(30 * time.Minute),
	})
	if err != nil {
		t.Fatalf("issue capability: %v", err)
	}

	agentRuntime, err := runtime.New(agentPrivateKey, fixedClock{now: issuedAt.Add(2 * time.Minute)})
	if err != nil {
		t.Fatalf("create runtime: %v", err)
	}
	actionEnvelope, err := agentRuntime.CreateActionEnvelope(runtime.ActionRequest{
		CapabilityID: capabilityToken.CapabilityID,
		ActionType:   "s3:PutObject",
		ActionPayload: json.RawMessage(`{
			"bucket":"integration-bucket",
			"key":"welcome.txt",
			"body":"hello"
		}`),
		ConstraintEvidence: domain.ConstraintEvidence{
			ResourceUsage: map[string]int64{"s3:objects": 1},
			SpendUsage:    map[string]int64{"usd_cents": 5},
			RateUsage:     map[string]int64{"requests_per_minute": 1},
			Environment:   "prod",
			APIScope:      "aws:s3",
		},
	})
	if err != nil {
		t.Fatalf("create action envelope: %v", err)
	}

	return verifyFixture{
		capability:      capabilityToken,
		action:          actionEnvelope,
		issuerPublicKey: anchorcrypto.PublicKeyToBase64(issuerPublicKey),
		agentPublicKey:  anchorcrypto.PublicKeyToBase64(agentPublicKey),
	}
}

func hasReason(reasons []string, fragment string) bool {
	for _, reason := range reasons {
		if strings.Contains(reason, fragment) {
			return true
		}
	}
	return false
}
