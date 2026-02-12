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

type supportClock struct {
	now time.Time
}

func (c supportClock) Now() time.Time {
	return c.now
}

type supportTicket struct {
	CustomerID string
	Subject    string
	Status     string
}

type fakeSupportService struct {
	verifier         *verifier.Engine
	revoked          map[string]struct{}
	processedActions map[string]struct{}
	tickets          map[string]supportTicket
}

func newFakeSupportService(revoked map[string]struct{}) *fakeSupportService {
	copyRevoked := make(map[string]struct{}, len(revoked))
	for id := range revoked {
		copyRevoked[id] = struct{}{}
	}
	return &fakeSupportService{
		verifier:         verifier.New(),
		revoked:          copyRevoked,
		processedActions: map[string]struct{}{},
		tickets:          map[string]supportTicket{},
	}
}

func (s *fakeSupportService) Execute(
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
		return supportReject("replay detected for action_id"), nil
	}

	switch actionEnvelope.ActionType {
	case "support:CreateTicket":
		if rejectResult, rejectErr := s.createTicket(actionEnvelope); rejectErr != nil {
			return domain.VerificationResult{}, rejectErr
		} else if rejectResult != nil {
			return *rejectResult, nil
		}
	case "support:ResolveTicket":
		if rejectResult, rejectErr := s.resolveTicket(actionEnvelope); rejectErr != nil {
			return domain.VerificationResult{}, rejectErr
		} else if rejectResult != nil {
			return *rejectResult, nil
		}
	default:
		return supportReject("fake support service does not implement this action"), nil
	}

	s.processedActions[actionEnvelope.ActionID] = struct{}{}
	return result, nil
}

func (s *fakeSupportService) createTicket(actionEnvelope domain.ActionEnvelope) (*domain.VerificationResult, error) {
	var payload struct {
		TicketID   string `json:"ticket_id"`
		CustomerID string `json:"customer_id"`
		Subject    string `json:"subject"`
		Body       string `json:"body"`
		Priority   string `json:"priority"`
		Channel    string `json:"channel"`
	}
	if err := json.Unmarshal(actionEnvelope.ActionPayload, &payload); err != nil {
		return nil, fmt.Errorf("parse support create payload: %w", err)
	}
	if payload.TicketID == "" || payload.CustomerID == "" || payload.Subject == "" {
		rejected := supportReject("ticket_id, customer_id, and subject are required")
		return &rejected, nil
	}
	if _, exists := s.tickets[payload.TicketID]; exists {
		rejected := supportReject("ticket_id already exists")
		return &rejected, nil
	}
	if payload.Priority != "low" && payload.Priority != "medium" && payload.Priority != "high" {
		rejected := supportReject("priority must be low, medium, or high")
		return &rejected, nil
	}
	if payload.Channel != "email" && payload.Channel != "chat" && payload.Channel != "phone" {
		rejected := supportReject("channel must be email, chat, or phone")
		return &rejected, nil
	}
	s.tickets[payload.TicketID] = supportTicket{CustomerID: payload.CustomerID, Subject: payload.Subject, Status: "open"}
	return nil, nil
}

func (s *fakeSupportService) resolveTicket(actionEnvelope domain.ActionEnvelope) (*domain.VerificationResult, error) {
	var payload struct {
		TicketID       string `json:"ticket_id"`
		ResolverID     string `json:"resolver_id"`
		ResolutionNote string `json:"resolution_note"`
	}
	if err := json.Unmarshal(actionEnvelope.ActionPayload, &payload); err != nil {
		return nil, fmt.Errorf("parse support resolve payload: %w", err)
	}
	if payload.TicketID == "" || payload.ResolverID == "" {
		rejected := supportReject("ticket_id and resolver_id are required")
		return &rejected, nil
	}
	ticket, exists := s.tickets[payload.TicketID]
	if !exists {
		rejected := supportReject("ticket_id does not exist")
		return &rejected, nil
	}
	if ticket.Status != "open" {
		rejected := supportReject("ticket is not open")
		return &rejected, nil
	}
	if len(payload.ResolutionNote) < 10 {
		rejected := supportReject("resolution_note must be at least 10 characters")
		return &rejected, nil
	}
	ticket.Status = "resolved"
	s.tickets[payload.TicketID] = ticket
	return nil, nil
}

func (s *fakeSupportService) ticket(ticketID string) (supportTicket, bool) {
	ticket, ok := s.tickets[ticketID]
	return ticket, ok
}

func supportReject(reason string) domain.VerificationResult {
	return domain.VerificationResult{Decision: domain.DecisionRejected, Reasons: []string{reason}}
}

func TestSupportDelegatedCreateTicketAuthorized(t *testing.T) {
	issuedAt := time.Date(2026, 2, 12, 23, 35, 0, 0, time.UTC)
	ctx := buildSupportDelegationContext(t, supportDelegationContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(20 * time.Minute),
		AllowedActions: []string{"support:CreateTicket"},
		Constraints:    defaultSupportConstraints(),
		NonceSeed:      0x81,
	})
	action := createSupportAction(t, ctx, supportActionInput{
		ActionTime: issuedAt.Add(1 * time.Minute),
		ActionType: "support:CreateTicket",
		ActionPayload: `{
			"ticket_id":"sup_1001",
			"customer_id":"cust_001",
			"subject":"Billing issue",
			"body":"Customer reported duplicate charge.",
			"priority":"high",
			"channel":"email"
		}`,
		Evidence: defaultSupportEvidence("support:tickets", "prod", 1, 1),
	})

	service := newFakeSupportService(map[string]struct{}{})
	result, err := service.Execute(ctx.capability, action, ctx.issuerPublicKey, ctx.agentPublicKey)
	if err != nil {
		t.Fatalf("execute support create ticket: %v", err)
	}
	if result.Decision != domain.DecisionAuthorized {
		t.Fatalf("expected AUTHORIZED, got %s with reasons %v", result.Decision, result.Reasons)
	}
	ticket, ok := service.ticket("sup_1001")
	if !ok || ticket.Status != "open" {
		t.Fatalf("expected ticket sup_1001 open, found=%v ticket=%+v", ok, ticket)
	}
}

func TestSupportDelegatedResolveTicketAuthorized(t *testing.T) {
	issuedAt := time.Date(2026, 2, 12, 23, 45, 0, 0, time.UTC)
	ctx := buildSupportDelegationContext(t, supportDelegationContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(25 * time.Minute),
		AllowedActions: []string{"support:CreateTicket", "support:ResolveTicket"},
		Constraints:    defaultSupportConstraints(),
		NonceSeed:      0x82,
	})
	createAction := createSupportAction(t, ctx, supportActionInput{
		ActionTime: issuedAt.Add(1 * time.Minute),
		ActionType: "support:CreateTicket",
		ActionPayload: `{
			"ticket_id":"sup_1002",
			"customer_id":"cust_002",
			"subject":"Password reset",
			"body":"Customer cannot sign in.",
			"priority":"medium",
			"channel":"chat"
		}`,
		Evidence: defaultSupportEvidence("support:tickets", "prod", 1, 1),
	})
	resolveAction := createSupportAction(t, ctx, supportActionInput{
		ActionTime: issuedAt.Add(2 * time.Minute),
		ActionType: "support:ResolveTicket",
		ActionPayload: `{
			"ticket_id":"sup_1002",
			"resolver_id":"agent_17",
			"resolution_note":"Reset link sent and verified by customer."
		}`,
		Evidence: defaultSupportEvidence("support:tickets", "prod", 1, 1),
	})

	service := newFakeSupportService(map[string]struct{}{})
	createResult, err := service.Execute(ctx.capability, createAction, ctx.issuerPublicKey, ctx.agentPublicKey)
	if err != nil {
		t.Fatalf("execute support create before resolve: %v", err)
	}
	if createResult.Decision != domain.DecisionAuthorized {
		t.Fatalf("expected create AUTHORIZED, got %s", createResult.Decision)
	}
	resolveResult, err := service.Execute(ctx.capability, resolveAction, ctx.issuerPublicKey, ctx.agentPublicKey)
	if err != nil {
		t.Fatalf("execute support resolve ticket: %v", err)
	}
	if resolveResult.Decision != domain.DecisionAuthorized {
		t.Fatalf("expected resolve AUTHORIZED, got %s", resolveResult.Decision)
	}
	ticket, _ := service.ticket("sup_1002")
	if ticket.Status != "resolved" {
		t.Fatalf("expected ticket sup_1002 resolved, got status=%s", ticket.Status)
	}
}

func TestSupportDelegatedRejectsMissingCustomerID(t *testing.T) {
	issuedAt := time.Date(2026, 2, 13, 0, 0, 0, 0, time.UTC)
	ctx := buildSupportDelegationContext(t, supportDelegationContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(20 * time.Minute),
		AllowedActions: []string{"support:CreateTicket"},
		Constraints:    defaultSupportConstraints(),
		NonceSeed:      0x83,
	})
	action := createSupportAction(t, ctx, supportActionInput{
		ActionTime: issuedAt.Add(1 * time.Minute),
		ActionType: "support:CreateTicket",
		ActionPayload: `{
			"ticket_id":"sup_1003",
			"customer_id":"",
			"subject":"Billing issue",
			"body":"Missing customer id",
			"priority":"high",
			"channel":"email"
		}`,
		Evidence: defaultSupportEvidence("support:tickets", "prod", 1, 1),
	})

	service := newFakeSupportService(map[string]struct{}{})
	result, err := service.Execute(ctx.capability, action, ctx.issuerPublicKey, ctx.agentPublicKey)
	if err != nil {
		t.Fatalf("execute support missing customer id: %v", err)
	}
	if result.Decision != domain.DecisionRejected {
		t.Fatalf("expected REJECTED, got %s", result.Decision)
	}
	if !hasReasonFragment(result.Reasons, "customer_id") {
		t.Fatalf("expected customer_id rejection, got %v", result.Reasons)
	}
}

func TestSupportDelegatedRejectsUnsupportedPriority(t *testing.T) {
	issuedAt := time.Date(2026, 2, 13, 0, 10, 0, 0, time.UTC)
	ctx := buildSupportDelegationContext(t, supportDelegationContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(20 * time.Minute),
		AllowedActions: []string{"support:CreateTicket"},
		Constraints:    defaultSupportConstraints(),
		NonceSeed:      0x84,
	})
	action := createSupportAction(t, ctx, supportActionInput{
		ActionTime: issuedAt.Add(1 * time.Minute),
		ActionType: "support:CreateTicket",
		ActionPayload: `{
			"ticket_id":"sup_1004",
			"customer_id":"cust_100",
			"subject":"API issue",
			"body":"Unclear priority value",
			"priority":"urgent",
			"channel":"email"
		}`,
		Evidence: defaultSupportEvidence("support:tickets", "prod", 1, 1),
	})

	service := newFakeSupportService(map[string]struct{}{})
	result, err := service.Execute(ctx.capability, action, ctx.issuerPublicKey, ctx.agentPublicKey)
	if err != nil {
		t.Fatalf("execute support unsupported priority: %v", err)
	}
	if result.Decision != domain.DecisionRejected {
		t.Fatalf("expected REJECTED, got %s", result.Decision)
	}
	if !hasReasonFragment(result.Reasons, "priority must be") {
		t.Fatalf("expected priority rejection, got %v", result.Reasons)
	}
}

func TestSupportDelegatedRejectsResolveMissingTicket(t *testing.T) {
	issuedAt := time.Date(2026, 2, 13, 0, 20, 0, 0, time.UTC)
	ctx := buildSupportDelegationContext(t, supportDelegationContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(20 * time.Minute),
		AllowedActions: []string{"support:ResolveTicket"},
		Constraints:    defaultSupportConstraints(),
		NonceSeed:      0x85,
	})
	action := createSupportAction(t, ctx, supportActionInput{
		ActionTime: issuedAt.Add(1 * time.Minute),
		ActionType: "support:ResolveTicket",
		ActionPayload: `{
			"ticket_id":"sup_missing",
			"resolver_id":"agent_42",
			"resolution_note":"Attempted fix but ticket does not exist."
		}`,
		Evidence: defaultSupportEvidence("support:tickets", "prod", 1, 1),
	})

	service := newFakeSupportService(map[string]struct{}{})
	result, err := service.Execute(ctx.capability, action, ctx.issuerPublicKey, ctx.agentPublicKey)
	if err != nil {
		t.Fatalf("execute support resolve missing ticket: %v", err)
	}
	if result.Decision != domain.DecisionRejected {
		t.Fatalf("expected REJECTED, got %s", result.Decision)
	}
	if !hasReasonFragment(result.Reasons, "ticket_id does not exist") {
		t.Fatalf("expected missing-ticket rejection, got %v", result.Reasons)
	}
}

func TestSupportDelegatedRejectsVerifierRateLimitExceeded(t *testing.T) {
	issuedAt := time.Date(2026, 2, 13, 0, 30, 0, 0, time.UTC)
	ctx := buildSupportDelegationContext(t, supportDelegationContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(20 * time.Minute),
		AllowedActions: []string{"support:CreateTicket"},
		Constraints:    defaultSupportConstraints(),
		NonceSeed:      0x86,
	})
	action := createSupportAction(t, ctx, supportActionInput{
		ActionTime: issuedAt.Add(1 * time.Minute),
		ActionType: "support:CreateTicket",
		ActionPayload: `{
			"ticket_id":"sup_1005",
			"customer_id":"cust_200",
			"subject":"Load issue",
			"body":"Burst traffic created many incidents.",
			"priority":"high",
			"channel":"phone"
		}`,
		Evidence: defaultSupportEvidence("support:tickets", "prod", 1, 8),
	})

	service := newFakeSupportService(map[string]struct{}{})
	result, err := service.Execute(ctx.capability, action, ctx.issuerPublicKey, ctx.agentPublicKey)
	if err != nil {
		t.Fatalf("execute support rate-limit exceeded: %v", err)
	}
	if result.Decision != domain.DecisionRejected {
		t.Fatalf("expected REJECTED, got %s", result.Decision)
	}
	if !hasReasonFragment(result.Reasons, "rate usage for requests_per_minute exceeds limit") {
		t.Fatalf("expected rate-limit rejection, got %v", result.Reasons)
	}
}

type supportDelegationContext struct {
	capability      domain.Capability
	issuerPublicKey string
	agentPublicKey  string
	agentPrivateKey ed25519.PrivateKey
}

type supportDelegationContextInput struct {
	IssuedAt       time.Time
	ExpiresAt      time.Time
	AllowedActions []string
	Constraints    domain.CapabilityConstraints
	NonceSeed      byte
}

type supportActionInput struct {
	ActionTime    time.Time
	ActionType    string
	ActionPayload string
	Evidence      domain.ConstraintEvidence
}

func buildSupportDelegationContext(t *testing.T, input supportDelegationContextInput) supportDelegationContext {
	t.Helper()
	issuerPublicKey, issuerPrivateKey, err := anchorcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate issuer key pair: %v", err)
	}
	agentPublicKey, agentPrivateKey, err := anchorcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate agent key pair: %v", err)
	}

	issuerService, err := issuer.NewService(issuerPrivateKey, bytes.NewReader(bytes.Repeat([]byte{input.NonceSeed}, 32)), supportClock{now: input.IssuedAt})
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
		t.Fatalf("issue support capability: %v", err)
	}

	return supportDelegationContext{
		capability:      capabilityToken,
		issuerPublicKey: anchorcrypto.PublicKeyToBase64(issuerPublicKey),
		agentPublicKey:  anchorcrypto.PublicKeyToBase64(agentPublicKey),
		agentPrivateKey: agentPrivateKey,
	}
}

func createSupportAction(t *testing.T, ctx supportDelegationContext, input supportActionInput) domain.ActionEnvelope {
	t.Helper()
	agentRuntime, err := runtime.New(ctx.agentPrivateKey, supportClock{now: input.ActionTime})
	if err != nil {
		t.Fatalf("create runtime: %v", err)
	}
	action, err := agentRuntime.CreateActionEnvelope(runtime.ActionRequest{
		CapabilityID:       ctx.capability.CapabilityID,
		ActionType:         input.ActionType,
		ActionPayload:      json.RawMessage(input.ActionPayload),
		ConstraintEvidence: input.Evidence,
	})
	if err != nil {
		t.Fatalf("create support action: %v", err)
	}
	return action
}

func defaultSupportConstraints() domain.CapabilityConstraints {
	return domain.CapabilityConstraints{
		ResourceLimits:         map[string]int64{"support:tickets": 5},
		SpendLimits:            map[string]int64{"usd_cents": 500},
		APIScopes:              []string{"support:tickets"},
		RateLimits:             map[string]int64{"requests_per_minute": 5},
		EnvironmentConstraints: []string{"prod"},
	}
}

func defaultSupportEvidence(scope, environment string, ticketUsage, rateUsage int64) domain.ConstraintEvidence {
	return domain.ConstraintEvidence{
		ResourceUsage: map[string]int64{"support:tickets": ticketUsage},
		SpendUsage:    map[string]int64{"usd_cents": 15},
		RateUsage:     map[string]int64{"requests_per_minute": rateUsage},
		Environment:   environment,
		APIScope:      scope,
	}
}
