package integration_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	anchorcrypto "github.com/ignyte-solutions/ignyte-anchor/internal/crypto"
	"github.com/ignyte-solutions/ignyte-anchor/internal/domain"
	"github.com/ignyte-solutions/ignyte-anchor/internal/issuer"
	"github.com/ignyte-solutions/ignyte-anchor/internal/runtime"
	"github.com/ignyte-solutions/ignyte-anchor/internal/verifier"
)

type payoutClock struct {
	now time.Time
}

func (c payoutClock) Now() time.Time {
	return c.now
}

type fakePayoutService struct {
	verifier *verifier.Engine
	revoked  map[string]struct{}
	payouts  map[string]int64
}

func newFakePayoutService(revoked map[string]struct{}) *fakePayoutService {
	copyRevoked := make(map[string]struct{}, len(revoked))
	for id := range revoked {
		copyRevoked[id] = struct{}{}
	}
	return &fakePayoutService{
		verifier: verifier.New(),
		revoked:  copyRevoked,
		payouts:  map[string]int64{},
	}
}

func (s *fakePayoutService) Execute(
	capabilityToken domain.Capability,
	actionEnvelope domain.ActionEnvelope,
	issuerPublicKey string,
	agentPublicKey string,
) (domain.VerificationResult, error) {
	parsedIssuerPublicKey, err := anchorcrypto.PublicKeyFromBase64(issuerPublicKey)
	if err != nil {
		return domain.VerificationResult{}, fmt.Errorf("parse issuer public key: %w", err)
	}
	parsedAgentPublicKey, err := anchorcrypto.PublicKeyFromBase64(agentPublicKey)
	if err != nil {
		return domain.VerificationResult{}, fmt.Errorf("parse agent public key: %w", err)
	}
	result := s.verifier.Verify(verifier.VerifyRequest{
		Capability:      capabilityToken,
		Action:          actionEnvelope,
		IssuerPublicKey: parsedIssuerPublicKey,
		AgentPublicKey:  parsedAgentPublicKey,
		ReferenceTime:   actionEnvelope.Timestamp,
		RevocationList:  verifier.StaticRevocationList{Revoked: s.revoked},
	})
	if result.Decision != domain.DecisionAuthorized {
		return result, nil
	}
	if actionEnvelope.ActionType != "payments:CreatePayout" {
		return domain.VerificationResult{Decision: domain.DecisionRejected, Reasons: []string{"fake payout service does not implement this action"}}, nil
	}

	var payload struct {
		PayoutID    string `json:"payout_id"`
		AmountCents int64  `json:"amount_cents"`
		Currency    string `json:"currency"`
	}
	if err := json.Unmarshal(actionEnvelope.ActionPayload, &payload); err != nil {
		return domain.VerificationResult{}, fmt.Errorf("parse payout payload: %w", err)
	}
	if payload.PayoutID == "" {
		return domain.VerificationResult{Decision: domain.DecisionRejected, Reasons: []string{"payout_id is required"}}, nil
	}
	if payload.AmountCents <= 0 {
		return domain.VerificationResult{Decision: domain.DecisionRejected, Reasons: []string{"amount_cents must be greater than zero"}}, nil
	}
	if payload.Currency != "USD" {
		return domain.VerificationResult{Decision: domain.DecisionRejected, Reasons: []string{"currency must be USD"}}, nil
	}
	s.payouts[payload.PayoutID] = payload.AmountCents
	return result, nil
}

func (s *fakePayoutService) payoutAmount(id string) (int64, bool) {
	amount, ok := s.payouts[id]
	return amount, ok
}

func TestDelegatedPayoutAuthorized(t *testing.T) {
	issuedAt := time.Date(2026, 2, 12, 21, 0, 0, 0, time.UTC)
	fixture := buildPayoutFixture(t, payoutFixtureInput{
		IssuedAt:        issuedAt,
		ExpiresAt:       issuedAt.Add(20 * time.Minute),
		ActionTime:      issuedAt.Add(2 * time.Minute),
		Environment:     "prod",
		ResourceUsage:   1,
		RateUsage:       1,
		PayoutID:        "pay_001",
		PayoutAmount:    3400,
		SpendUsageCents: 3400,
	})
	service := newFakePayoutService(map[string]struct{}{})

	result, err := service.Execute(fixture.capability, fixture.action, fixture.issuerPublicKey, fixture.agentPublicKey)
	if err != nil {
		t.Fatalf("execute payout action: %v", err)
	}
	if result.Decision != domain.DecisionAuthorized {
		t.Fatalf("expected AUTHORIZED, got %s with reasons %v", result.Decision, result.Reasons)
	}
	if amount, ok := service.payoutAmount("pay_001"); !ok || amount != 3400 {
		t.Fatalf("expected payout to be recorded, found=%v amount=%d", ok, amount)
	}
}

func TestDelegatedPayoutRejectedWhenCapabilityExpired(t *testing.T) {
	issuedAt := time.Date(2026, 2, 12, 21, 0, 0, 0, time.UTC)
	fixture := buildPayoutFixture(t, payoutFixtureInput{
		IssuedAt:        issuedAt,
		ExpiresAt:       issuedAt.Add(1 * time.Minute),
		ActionTime:      issuedAt.Add(5 * time.Minute),
		Environment:     "prod",
		ResourceUsage:   1,
		RateUsage:       1,
		PayoutID:        "pay_002",
		PayoutAmount:    1500,
		SpendUsageCents: 1500,
	})
	service := newFakePayoutService(map[string]struct{}{})

	result, err := service.Execute(fixture.capability, fixture.action, fixture.issuerPublicKey, fixture.agentPublicKey)
	if err != nil {
		t.Fatalf("execute expired payout action: %v", err)
	}
	if result.Decision != domain.DecisionRejected {
		t.Fatalf("expected REJECTED, got %s", result.Decision)
	}
	if !hasReasonFragment(result.Reasons, "capability is expired") {
		t.Fatalf("expected expiry rejection reason, got %v", result.Reasons)
	}
	if _, ok := service.payoutAmount("pay_002"); ok {
		t.Fatal("expected no payout to be recorded after rejection")
	}
}

func TestDelegatedPayoutRejectedWhenRevoked(t *testing.T) {
	issuedAt := time.Date(2026, 2, 12, 21, 0, 0, 0, time.UTC)
	fixture := buildPayoutFixture(t, payoutFixtureInput{
		IssuedAt:        issuedAt,
		ExpiresAt:       issuedAt.Add(20 * time.Minute),
		ActionTime:      issuedAt.Add(2 * time.Minute),
		Environment:     "prod",
		ResourceUsage:   1,
		RateUsage:       1,
		PayoutID:        "pay_003",
		PayoutAmount:    2600,
		SpendUsageCents: 2600,
	})
	service := newFakePayoutService(map[string]struct{}{
		fixture.capability.CapabilityID: {},
	})

	result, err := service.Execute(fixture.capability, fixture.action, fixture.issuerPublicKey, fixture.agentPublicKey)
	if err != nil {
		t.Fatalf("execute revoked payout action: %v", err)
	}
	if result.Decision != domain.DecisionRejected {
		t.Fatalf("expected REJECTED, got %s", result.Decision)
	}
	if !hasReasonFragment(result.Reasons, "capability is revoked") {
		t.Fatalf("expected revocation rejection reason, got %v", result.Reasons)
	}
	if _, ok := service.payoutAmount("pay_003"); ok {
		t.Fatal("expected no payout to be recorded for revoked capability")
	}
}

type payoutFixture struct {
	capability      domain.Capability
	action          domain.ActionEnvelope
	issuerPublicKey string
	agentPublicKey  string
}

type payoutFixtureInput struct {
	IssuedAt        time.Time
	ExpiresAt       time.Time
	ActionTime      time.Time
	Environment     string
	ResourceUsage   int64
	RateUsage       int64
	PayoutID        string
	PayoutAmount    int64
	SpendUsageCents int64
}

func buildPayoutFixture(t *testing.T, input payoutFixtureInput) payoutFixture {
	t.Helper()
	issuerPublicKey, issuerPrivateKey, err := anchorcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate issuer key pair: %v", err)
	}
	agentPublicKey, agentPrivateKey, err := anchorcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate agent key pair: %v", err)
	}

	issuerService, err := issuer.NewService(issuerPrivateKey, bytes.NewReader(bytes.Repeat([]byte{0x41}, 32)), payoutClock{now: input.IssuedAt})
	if err != nil {
		t.Fatalf("create issuer service: %v", err)
	}
	capabilityToken, err := issuerService.IssueCapability(issuer.IssueCapabilityRequest{
		AgentPublicKey: anchorcrypto.PublicKeyToBase64(agentPublicKey),
		AllowedActions: []string{"payments:CreatePayout"},
		Constraints: domain.CapabilityConstraints{
			ResourceLimits:         map[string]int64{"payments:payouts": 1},
			SpendLimits:            map[string]int64{"usd_cents": 5_000},
			APIScopes:              []string{"payments:payouts"},
			RateLimits:             map[string]int64{"requests_per_minute": 3},
			EnvironmentConstraints: []string{"prod"},
		},
		ExpiresAt: input.ExpiresAt,
	})
	if err != nil {
		t.Fatalf("issue payout capability: %v", err)
	}

	agentRuntime, err := runtime.New(agentPrivateKey, payoutClock{now: input.ActionTime})
	if err != nil {
		t.Fatalf("create agent runtime: %v", err)
	}
	actionEnvelope, err := agentRuntime.CreateActionEnvelope(runtime.ActionRequest{
		CapabilityID: capabilityToken.CapabilityID,
		ActionType:   "payments:CreatePayout",
		ActionPayload: json.RawMessage(fmt.Sprintf(`{
			"payout_id":"%s",
			"amount_cents":%d,
			"currency":"USD"
		}`, input.PayoutID, input.PayoutAmount)),
		ConstraintEvidence: domain.ConstraintEvidence{
			ResourceUsage: map[string]int64{"payments:payouts": input.ResourceUsage},
			SpendUsage:    map[string]int64{"usd_cents": input.SpendUsageCents},
			RateUsage:     map[string]int64{"requests_per_minute": input.RateUsage},
			Environment:   input.Environment,
			APIScope:      "payments:payouts",
		},
	})
	if err != nil {
		t.Fatalf("create payout action envelope: %v", err)
	}

	return payoutFixture{
		capability:      capabilityToken,
		action:          actionEnvelope,
		issuerPublicKey: anchorcrypto.PublicKeyToBase64(issuerPublicKey),
		agentPublicKey:  anchorcrypto.PublicKeyToBase64(agentPublicKey),
	}
}
