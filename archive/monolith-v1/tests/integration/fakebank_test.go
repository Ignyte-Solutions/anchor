package integration_test

import (
	"bytes"
	"crypto/ed25519"
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

type bankClock struct {
	now time.Time
}

func (c bankClock) Now() time.Time {
	return c.now
}

type fakeBankService struct {
	verifier             *verifier.Engine
	revoked              map[string]struct{}
	balances             map[string]int64
	processedActions     map[string]struct{}
	processedTransferIDs map[string]struct{}
	dailyTransferred     map[string]int64
	dailyTransferCap     int64
}

func newFakeBankService(initialBalances map[string]int64, revoked map[string]struct{}, dailyTransferCap int64) *fakeBankService {
	balances := make(map[string]int64, len(initialBalances))
	for account, amount := range initialBalances {
		balances[account] = amount
	}
	copyRevoked := make(map[string]struct{}, len(revoked))
	for id := range revoked {
		copyRevoked[id] = struct{}{}
	}
	return &fakeBankService{
		verifier:             verifier.New(),
		revoked:              copyRevoked,
		balances:             balances,
		processedActions:     map[string]struct{}{},
		processedTransferIDs: map[string]struct{}{},
		dailyTransferred:     map[string]int64{},
		dailyTransferCap:     dailyTransferCap,
	}
}

func (s *fakeBankService) Execute(
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
	if _, exists := s.processedActions[actionEnvelope.ActionID]; exists {
		return bankReject("replay detected for action_id"), nil
	}
	if actionEnvelope.ActionType != "bank:TransferFunds" {
		return bankReject("fake bank service does not implement this action"), nil
	}

	var payload struct {
		TransferID  string `json:"transfer_id"`
		FromAccount string `json:"from_account"`
		ToAccount   string `json:"to_account"`
		AmountCents int64  `json:"amount_cents"`
		Currency    string `json:"currency"`
		Reference   string `json:"reference"`
	}
	if err := json.Unmarshal(actionEnvelope.ActionPayload, &payload); err != nil {
		return domain.VerificationResult{}, fmt.Errorf("parse bank action payload: %w", err)
	}
	if payload.TransferID == "" {
		return bankReject("transfer_id is required"), nil
	}
	if _, exists := s.processedTransferIDs[payload.TransferID]; exists {
		return bankReject("duplicate transfer_id"), nil
	}
	if payload.FromAccount == "" || payload.ToAccount == "" {
		return bankReject("from_account and to_account are required"), nil
	}
	if payload.FromAccount == payload.ToAccount {
		return bankReject("from_account and to_account must differ"), nil
	}
	if payload.AmountCents <= 0 {
		return bankReject("amount_cents must be greater than zero"), nil
	}
	if payload.Currency != "USD" {
		return bankReject("currency must be USD"), nil
	}
	if s.dailyTransferred[payload.FromAccount]+payload.AmountCents > s.dailyTransferCap {
		return bankReject("daily transfer cap exceeded"), nil
	}
	if s.balances[payload.FromAccount] < payload.AmountCents {
		return bankReject("insufficient funds"), nil
	}

	s.balances[payload.FromAccount] = s.balances[payload.FromAccount] - payload.AmountCents
	s.balances[payload.ToAccount] = s.balances[payload.ToAccount] + payload.AmountCents
	s.dailyTransferred[payload.FromAccount] = s.dailyTransferred[payload.FromAccount] + payload.AmountCents
	s.processedTransferIDs[payload.TransferID] = struct{}{}
	s.processedActions[actionEnvelope.ActionID] = struct{}{}
	return result, nil
}

func (s *fakeBankService) balance(account string) int64 {
	return s.balances[account]
}

func bankReject(reason string) domain.VerificationResult {
	return domain.VerificationResult{Decision: domain.DecisionRejected, Reasons: []string{reason}}
}

func TestBankDelegatedTransferAuthorized(t *testing.T) {
	issuedAt := time.Date(2026, 2, 12, 20, 0, 0, 0, time.UTC)
	ctx := buildBankDelegationContext(t, bankDelegationContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(30 * time.Minute),
		AllowedActions: []string{"bank:TransferFunds"},
		Constraints:    defaultBankConstraints(),
		NonceSeed:      0x61,
	})
	action := createBankTransferAction(t, ctx, bankActionInput{
		ActionTime:    issuedAt.Add(2 * time.Minute),
		TransferID:    "tr_1001",
		FromAccount:   "operating",
		ToAccount:     "vendor",
		AmountCents:   2500,
		Reference:     "invoice-2026-01",
		Scope:         "bank:payments",
		Environment:   "prod",
		ResourceUsage: 1,
		SpendUsage:    2500,
		RateUsage:     1,
	})

	service := newFakeBankService(map[string]int64{"operating": 100_000, "vendor": 0}, map[string]struct{}{}, 30_000)
	result, err := service.Execute(ctx.capability, action, ctx.issuerPublicKey, ctx.agentPublicKey)
	if err != nil {
		t.Fatalf("execute bank transfer: %v", err)
	}
	if result.Decision != domain.DecisionAuthorized {
		t.Fatalf("expected AUTHORIZED, got %s with reasons %v", result.Decision, result.Reasons)
	}
	if service.balance("operating") != 97_500 || service.balance("vendor") != 2_500 {
		t.Fatalf("unexpected balances after transfer: operating=%d vendor=%d", service.balance("operating"), service.balance("vendor"))
	}
}

func TestBankDelegatedRejectsInsufficientFunds(t *testing.T) {
	issuedAt := time.Date(2026, 2, 12, 20, 15, 0, 0, time.UTC)
	ctx := buildBankDelegationContext(t, bankDelegationContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(30 * time.Minute),
		AllowedActions: []string{"bank:TransferFunds"},
		Constraints:    defaultBankConstraints(),
		NonceSeed:      0x62,
	})
	action := createBankTransferAction(t, ctx, bankActionInput{
		ActionTime:    issuedAt.Add(2 * time.Minute),
		TransferID:    "tr_1002",
		FromAccount:   "operating",
		ToAccount:     "vendor",
		AmountCents:   9_000,
		Reference:     "invoice-2026-02",
		Scope:         "bank:payments",
		Environment:   "prod",
		ResourceUsage: 1,
		SpendUsage:    9_000,
		RateUsage:     1,
	})

	service := newFakeBankService(map[string]int64{"operating": 1_000, "vendor": 0}, map[string]struct{}{}, 30_000)
	result, err := service.Execute(ctx.capability, action, ctx.issuerPublicKey, ctx.agentPublicKey)
	if err != nil {
		t.Fatalf("execute insufficient-funds transfer: %v", err)
	}
	if result.Decision != domain.DecisionRejected {
		t.Fatalf("expected REJECTED, got %s", result.Decision)
	}
	if !hasReasonFragment(result.Reasons, "insufficient funds") {
		t.Fatalf("expected insufficient funds reason, got %v", result.Reasons)
	}
}

func TestBankDelegatedRejectsDuplicateTransferID(t *testing.T) {
	issuedAt := time.Date(2026, 2, 12, 20, 30, 0, 0, time.UTC)
	ctx := buildBankDelegationContext(t, bankDelegationContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(30 * time.Minute),
		AllowedActions: []string{"bank:TransferFunds"},
		Constraints:    defaultBankConstraints(),
		NonceSeed:      0x63,
	})
	first := createBankTransferAction(t, ctx, bankActionInput{
		ActionTime:    issuedAt.Add(2 * time.Minute),
		TransferID:    "tr_1003",
		FromAccount:   "operating",
		ToAccount:     "vendor-a",
		AmountCents:   1500,
		Reference:     "invoice-a",
		Scope:         "bank:payments",
		Environment:   "prod",
		ResourceUsage: 1,
		SpendUsage:    1500,
		RateUsage:     1,
	})
	second := createBankTransferAction(t, ctx, bankActionInput{
		ActionTime:    issuedAt.Add(3 * time.Minute),
		TransferID:    "tr_1003",
		FromAccount:   "operating",
		ToAccount:     "vendor-b",
		AmountCents:   1200,
		Reference:     "invoice-b",
		Scope:         "bank:payments",
		Environment:   "prod",
		ResourceUsage: 1,
		SpendUsage:    1200,
		RateUsage:     1,
	})

	service := newFakeBankService(map[string]int64{"operating": 100_000, "vendor-a": 0, "vendor-b": 0}, map[string]struct{}{}, 30_000)
	firstResult, err := service.Execute(ctx.capability, first, ctx.issuerPublicKey, ctx.agentPublicKey)
	if err != nil {
		t.Fatalf("execute first transfer: %v", err)
	}
	if firstResult.Decision != domain.DecisionAuthorized {
		t.Fatalf("expected first transfer AUTHORIZED, got %s", firstResult.Decision)
	}

	secondResult, err := service.Execute(ctx.capability, second, ctx.issuerPublicKey, ctx.agentPublicKey)
	if err != nil {
		t.Fatalf("execute second transfer with duplicate id: %v", err)
	}
	if secondResult.Decision != domain.DecisionRejected {
		t.Fatalf("expected duplicate transfer to be REJECTED, got %s", secondResult.Decision)
	}
	if !hasReasonFragment(secondResult.Reasons, "duplicate transfer_id") {
		t.Fatalf("expected duplicate transfer_id reason, got %v", secondResult.Reasons)
	}
}

func TestBankDelegatedRejectsReplayActionEnvelope(t *testing.T) {
	issuedAt := time.Date(2026, 2, 12, 20, 45, 0, 0, time.UTC)
	ctx := buildBankDelegationContext(t, bankDelegationContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(30 * time.Minute),
		AllowedActions: []string{"bank:TransferFunds"},
		Constraints:    defaultBankConstraints(),
		NonceSeed:      0x64,
	})
	action := createBankTransferAction(t, ctx, bankActionInput{
		ActionTime:    issuedAt.Add(2 * time.Minute),
		TransferID:    "tr_1004",
		FromAccount:   "operating",
		ToAccount:     "vendor",
		AmountCents:   1800,
		Reference:     "invoice-2026-03",
		Scope:         "bank:payments",
		Environment:   "prod",
		ResourceUsage: 1,
		SpendUsage:    1800,
		RateUsage:     1,
	})

	service := newFakeBankService(map[string]int64{"operating": 100_000, "vendor": 0}, map[string]struct{}{}, 30_000)
	first, err := service.Execute(ctx.capability, action, ctx.issuerPublicKey, ctx.agentPublicKey)
	if err != nil {
		t.Fatalf("execute first transfer: %v", err)
	}
	if first.Decision != domain.DecisionAuthorized {
		t.Fatalf("expected first transfer AUTHORIZED, got %s", first.Decision)
	}
	second, err := service.Execute(ctx.capability, action, ctx.issuerPublicKey, ctx.agentPublicKey)
	if err != nil {
		t.Fatalf("execute replay transfer: %v", err)
	}
	if second.Decision != domain.DecisionRejected {
		t.Fatalf("expected replay REJECTED, got %s", second.Decision)
	}
	if !hasReasonFragment(second.Reasons, "replay detected") {
		t.Fatalf("expected replay rejection reason, got %v", second.Reasons)
	}
}

func TestBankDelegatedRejectsVerifierSpendLimitExceeded(t *testing.T) {
	issuedAt := time.Date(2026, 2, 12, 21, 0, 0, 0, time.UTC)
	ctx := buildBankDelegationContext(t, bankDelegationContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(30 * time.Minute),
		AllowedActions: []string{"bank:TransferFunds"},
		Constraints:    defaultBankConstraints(),
		NonceSeed:      0x65,
	})
	action := createBankTransferAction(t, ctx, bankActionInput{
		ActionTime:    issuedAt.Add(2 * time.Minute),
		TransferID:    "tr_1005",
		FromAccount:   "operating",
		ToAccount:     "vendor",
		AmountCents:   12_000,
		Reference:     "invoice-2026-04",
		Scope:         "bank:payments",
		Environment:   "prod",
		ResourceUsage: 1,
		SpendUsage:    12_000,
		RateUsage:     1,
	})

	service := newFakeBankService(map[string]int64{"operating": 100_000, "vendor": 0}, map[string]struct{}{}, 30_000)
	result, err := service.Execute(ctx.capability, action, ctx.issuerPublicKey, ctx.agentPublicKey)
	if err != nil {
		t.Fatalf("execute spend-limit transfer: %v", err)
	}
	if result.Decision != domain.DecisionRejected {
		t.Fatalf("expected REJECTED, got %s", result.Decision)
	}
	if !hasReasonFragment(result.Reasons, "spend usage for usd_cents exceeds limit") {
		t.Fatalf("expected spend-limit rejection reason, got %v", result.Reasons)
	}
}

func TestBankDelegatedRejectsVerifierRateLimitExceeded(t *testing.T) {
	issuedAt := time.Date(2026, 2, 12, 21, 15, 0, 0, time.UTC)
	ctx := buildBankDelegationContext(t, bankDelegationContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(30 * time.Minute),
		AllowedActions: []string{"bank:TransferFunds"},
		Constraints:    defaultBankConstraints(),
		NonceSeed:      0x66,
	})
	action := createBankTransferAction(t, ctx, bankActionInput{
		ActionTime:    issuedAt.Add(2 * time.Minute),
		TransferID:    "tr_1006",
		FromAccount:   "operating",
		ToAccount:     "vendor",
		AmountCents:   1200,
		Reference:     "invoice-2026-05",
		Scope:         "bank:payments",
		Environment:   "prod",
		ResourceUsage: 1,
		SpendUsage:    1200,
		RateUsage:     9,
	})

	service := newFakeBankService(map[string]int64{"operating": 100_000, "vendor": 0}, map[string]struct{}{}, 30_000)
	result, err := service.Execute(ctx.capability, action, ctx.issuerPublicKey, ctx.agentPublicKey)
	if err != nil {
		t.Fatalf("execute rate-limit transfer: %v", err)
	}
	if result.Decision != domain.DecisionRejected {
		t.Fatalf("expected REJECTED, got %s", result.Decision)
	}
	if !hasReasonFragment(result.Reasons, "rate usage for requests_per_minute exceeds limit") {
		t.Fatalf("expected rate-limit rejection reason, got %v", result.Reasons)
	}
}

func TestBankDelegatedRejectsExpiredCapability(t *testing.T) {
	issuedAt := time.Date(2026, 2, 12, 21, 30, 0, 0, time.UTC)
	ctx := buildBankDelegationContext(t, bankDelegationContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(1 * time.Minute),
		AllowedActions: []string{"bank:TransferFunds"},
		Constraints:    defaultBankConstraints(),
		NonceSeed:      0x67,
	})
	action := createBankTransferAction(t, ctx, bankActionInput{
		ActionTime:    issuedAt.Add(5 * time.Minute),
		TransferID:    "tr_1007",
		FromAccount:   "operating",
		ToAccount:     "vendor",
		AmountCents:   1500,
		Reference:     "invoice-2026-06",
		Scope:         "bank:payments",
		Environment:   "prod",
		ResourceUsage: 1,
		SpendUsage:    1500,
		RateUsage:     1,
	})

	service := newFakeBankService(map[string]int64{"operating": 100_000, "vendor": 0}, map[string]struct{}{}, 30_000)
	result, err := service.Execute(ctx.capability, action, ctx.issuerPublicKey, ctx.agentPublicKey)
	if err != nil {
		t.Fatalf("execute expired transfer: %v", err)
	}
	if result.Decision != domain.DecisionRejected {
		t.Fatalf("expected REJECTED, got %s", result.Decision)
	}
	if !hasReasonFragment(result.Reasons, "capability is expired") {
		t.Fatalf("expected expiry rejection reason, got %v", result.Reasons)
	}
}

func TestBankDelegatedRejectsEnvironmentMismatch(t *testing.T) {
	issuedAt := time.Date(2026, 2, 12, 21, 45, 0, 0, time.UTC)
	ctx := buildBankDelegationContext(t, bankDelegationContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(30 * time.Minute),
		AllowedActions: []string{"bank:TransferFunds"},
		Constraints:    defaultBankConstraints(),
		NonceSeed:      0x68,
	})
	action := createBankTransferAction(t, ctx, bankActionInput{
		ActionTime:    issuedAt.Add(2 * time.Minute),
		TransferID:    "tr_1008",
		FromAccount:   "operating",
		ToAccount:     "vendor",
		AmountCents:   1100,
		Reference:     "invoice-2026-07",
		Scope:         "bank:payments",
		Environment:   "staging",
		ResourceUsage: 1,
		SpendUsage:    1100,
		RateUsage:     1,
	})

	service := newFakeBankService(map[string]int64{"operating": 100_000, "vendor": 0}, map[string]struct{}{}, 30_000)
	result, err := service.Execute(ctx.capability, action, ctx.issuerPublicKey, ctx.agentPublicKey)
	if err != nil {
		t.Fatalf("execute env mismatch transfer: %v", err)
	}
	if result.Decision != domain.DecisionRejected {
		t.Fatalf("expected REJECTED, got %s", result.Decision)
	}
	if !hasReasonFragment(result.Reasons, "environment is not allowed") {
		t.Fatalf("expected environment rejection reason, got %v", result.Reasons)
	}
}

func TestBankDelegatedRejectsDailyAccountCapExceeded(t *testing.T) {
	issuedAt := time.Date(2026, 2, 12, 22, 0, 0, 0, time.UTC)
	ctx := buildBankDelegationContext(t, bankDelegationContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(30 * time.Minute),
		AllowedActions: []string{"bank:TransferFunds"},
		Constraints:    defaultBankConstraints(),
		NonceSeed:      0x69,
	})
	first := createBankTransferAction(t, ctx, bankActionInput{
		ActionTime:    issuedAt.Add(1 * time.Minute),
		TransferID:    "tr_1009",
		FromAccount:   "operating",
		ToAccount:     "vendor-a",
		AmountCents:   3000,
		Reference:     "invoice-a",
		Scope:         "bank:payments",
		Environment:   "prod",
		ResourceUsage: 1,
		SpendUsage:    3000,
		RateUsage:     1,
	})
	second := createBankTransferAction(t, ctx, bankActionInput{
		ActionTime:    issuedAt.Add(2 * time.Minute),
		TransferID:    "tr_1010",
		FromAccount:   "operating",
		ToAccount:     "vendor-b",
		AmountCents:   3200,
		Reference:     "invoice-b",
		Scope:         "bank:payments",
		Environment:   "prod",
		ResourceUsage: 1,
		SpendUsage:    3200,
		RateUsage:     1,
	})

	service := newFakeBankService(map[string]int64{"operating": 100_000, "vendor-a": 0, "vendor-b": 0}, map[string]struct{}{}, 6_000)
	result1, err := service.Execute(ctx.capability, first, ctx.issuerPublicKey, ctx.agentPublicKey)
	if err != nil {
		t.Fatalf("execute first daily-cap transfer: %v", err)
	}
	if result1.Decision != domain.DecisionAuthorized {
		t.Fatalf("expected first transfer AUTHORIZED, got %s", result1.Decision)
	}
	result2, err := service.Execute(ctx.capability, second, ctx.issuerPublicKey, ctx.agentPublicKey)
	if err != nil {
		t.Fatalf("execute second daily-cap transfer: %v", err)
	}
	if result2.Decision != domain.DecisionRejected {
		t.Fatalf("expected second transfer REJECTED, got %s", result2.Decision)
	}
	if !hasReasonFragment(result2.Reasons, "daily transfer cap exceeded") {
		t.Fatalf("expected daily cap rejection, got %v", result2.Reasons)
	}
}

type bankDelegationContext struct {
	capability      domain.Capability
	issuerPublicKey string
	agentPublicKey  string
	agentPrivateKey ed25519.PrivateKey
}

type bankDelegationContextInput struct {
	IssuedAt       time.Time
	ExpiresAt      time.Time
	AllowedActions []string
	Constraints    domain.CapabilityConstraints
	NonceSeed      byte
}

type bankActionInput struct {
	ActionTime    time.Time
	TransferID    string
	FromAccount   string
	ToAccount     string
	AmountCents   int64
	Reference     string
	Scope         string
	Environment   string
	ResourceUsage int64
	SpendUsage    int64
	RateUsage     int64
}

func buildBankDelegationContext(t *testing.T, input bankDelegationContextInput) bankDelegationContext {
	t.Helper()
	issuerPublicKey, issuerPrivateKey, err := anchorcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate issuer key pair: %v", err)
	}
	agentPublicKey, agentPrivateKey, err := anchorcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate agent key pair: %v", err)
	}

	issuerService, err := issuer.NewService(issuerPrivateKey, bytes.NewReader(bytes.Repeat([]byte{input.NonceSeed}, 32)), bankClock{now: input.IssuedAt})
	if err != nil {
		t.Fatalf("create issuer service: %v", err)
	}
	capabilityToken, err := issuerService.IssueCapability(issuer.IssueCapabilityRequest{
		AgentPublicKey: anchorcrypto.PublicKeyToBase64(agentPublicKey),
		AllowedActions: input.AllowedActions,
		Constraints:    input.Constraints,
		ExpiresAt:      input.ExpiresAt,
	})
	if err != nil {
		t.Fatalf("issue bank capability: %v", err)
	}

	return bankDelegationContext{
		capability:      capabilityToken,
		issuerPublicKey: anchorcrypto.PublicKeyToBase64(issuerPublicKey),
		agentPublicKey:  anchorcrypto.PublicKeyToBase64(agentPublicKey),
		agentPrivateKey: agentPrivateKey,
	}
}

func createBankTransferAction(t *testing.T, ctx bankDelegationContext, input bankActionInput) domain.ActionEnvelope {
	t.Helper()
	agentRuntime, err := runtime.New(ctx.agentPrivateKey, bankClock{now: input.ActionTime})
	if err != nil {
		t.Fatalf("create runtime: %v", err)
	}
	action, err := agentRuntime.CreateActionEnvelope(runtime.ActionRequest{
		CapabilityID: ctx.capability.CapabilityID,
		ActionType:   "bank:TransferFunds",
		ActionPayload: json.RawMessage(fmt.Sprintf(`{
			"transfer_id":"%s",
			"from_account":"%s",
			"to_account":"%s",
			"amount_cents":%d,
			"currency":"USD",
			"reference":"%s"
		}`, input.TransferID, input.FromAccount, input.ToAccount, input.AmountCents, input.Reference)),
		ConstraintEvidence: domain.ConstraintEvidence{
			ResourceUsage: map[string]int64{"bank:transfers": input.ResourceUsage},
			SpendUsage:    map[string]int64{"usd_cents": input.SpendUsage},
			RateUsage:     map[string]int64{"requests_per_minute": input.RateUsage},
			Environment:   input.Environment,
			APIScope:      input.Scope,
		},
	})
	if err != nil {
		t.Fatalf("create transfer action: %v", err)
	}
	return action
}

func defaultBankConstraints() domain.CapabilityConstraints {
	return domain.CapabilityConstraints{
		ResourceLimits:         map[string]int64{"bank:transfers": 5},
		SpendLimits:            map[string]int64{"usd_cents": 10_000},
		APIScopes:              []string{"bank:payments"},
		RateLimits:             map[string]int64{"requests_per_minute": 5},
		EnvironmentConstraints: []string{"prod"},
	}
}
