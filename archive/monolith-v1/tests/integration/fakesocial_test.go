package integration_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	anchorcrypto "github.com/ignyte-solutions/ignyte-anchor/internal/crypto"
	"github.com/ignyte-solutions/ignyte-anchor/internal/domain"
	"github.com/ignyte-solutions/ignyte-anchor/internal/issuer"
	"github.com/ignyte-solutions/ignyte-anchor/internal/runtime"
	"github.com/ignyte-solutions/ignyte-anchor/internal/verifier"
)

type socialClock struct {
	now time.Time
}

func (c socialClock) Now() time.Time {
	return c.now
}

type socialPost struct {
	AccountID  string
	Content    string
	Visibility string
}

type fakeSocialMediaService struct {
	verifier         *verifier.Engine
	revoked          map[string]struct{}
	processedActions map[string]struct{}
	allowedAccounts  map[string]struct{}
	bannedWords      []string
	posts            map[string]socialPost
}

func newFakeSocialMediaService(revoked map[string]struct{}) *fakeSocialMediaService {
	copyRevoked := make(map[string]struct{}, len(revoked))
	for id := range revoked {
		copyRevoked[id] = struct{}{}
	}
	return &fakeSocialMediaService{
		verifier:         verifier.New(),
		revoked:          copyRevoked,
		processedActions: map[string]struct{}{},
		allowedAccounts: map[string]struct{}{
			"ignyte-main":    {},
			"ignyte-support": {},
		},
		bannedWords: []string{"guaranteed returns", "leak"},
		posts:       map[string]socialPost{},
	}
}

func (s *fakeSocialMediaService) Execute(
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
		return socialReject("replay detected for action_id"), nil
	}

	switch actionEnvelope.ActionType {
	case "social:PublishPost":
		if rejectResult, rejectErr := s.publishPost(actionEnvelope); rejectErr != nil {
			return domain.VerificationResult{}, rejectErr
		} else if rejectResult != nil {
			return *rejectResult, nil
		}
	case "social:DeletePost":
		if rejectResult, rejectErr := s.deletePost(actionEnvelope); rejectErr != nil {
			return domain.VerificationResult{}, rejectErr
		} else if rejectResult != nil {
			return *rejectResult, nil
		}
	default:
		return socialReject("fake social media service does not implement this action"), nil
	}

	s.processedActions[actionEnvelope.ActionID] = struct{}{}
	return result, nil
}

func (s *fakeSocialMediaService) publishPost(actionEnvelope domain.ActionEnvelope) (*domain.VerificationResult, error) {
	var payload struct {
		PostID     string `json:"post_id"`
		AccountID  string `json:"account_id"`
		Content    string `json:"content"`
		Visibility string `json:"visibility"`
	}
	if err := json.Unmarshal(actionEnvelope.ActionPayload, &payload); err != nil {
		return nil, fmt.Errorf("parse social publish payload: %w", err)
	}
	if payload.PostID == "" || payload.AccountID == "" || payload.Content == "" {
		rejected := socialReject("post_id, account_id, and content are required")
		return &rejected, nil
	}
	if _, exists := s.allowedAccounts[payload.AccountID]; !exists {
		rejected := socialReject("account_id is not authorized")
		return &rejected, nil
	}
	if _, exists := s.posts[payload.PostID]; exists {
		rejected := socialReject("post_id already exists")
		return &rejected, nil
	}
	if len(payload.Content) > 280 {
		rejected := socialReject("content exceeds 280 characters")
		return &rejected, nil
	}
	if containsBannedContent(payload.Content, s.bannedWords) {
		rejected := socialReject("content failed moderation")
		return &rejected, nil
	}
	if payload.Visibility != "public" && payload.Visibility != "followers" && payload.Visibility != "private" {
		rejected := socialReject("visibility must be public, followers, or private")
		return &rejected, nil
	}

	s.posts[payload.PostID] = socialPost{AccountID: payload.AccountID, Content: payload.Content, Visibility: payload.Visibility}
	return nil, nil
}

func (s *fakeSocialMediaService) deletePost(actionEnvelope domain.ActionEnvelope) (*domain.VerificationResult, error) {
	var payload struct {
		PostID    string `json:"post_id"`
		AccountID string `json:"account_id"`
	}
	if err := json.Unmarshal(actionEnvelope.ActionPayload, &payload); err != nil {
		return nil, fmt.Errorf("parse social delete payload: %w", err)
	}
	if payload.PostID == "" || payload.AccountID == "" {
		rejected := socialReject("post_id and account_id are required")
		return &rejected, nil
	}
	post, exists := s.posts[payload.PostID]
	if !exists {
		rejected := socialReject("post_id does not exist")
		return &rejected, nil
	}
	if post.AccountID != payload.AccountID {
		rejected := socialReject("post does not belong to account_id")
		return &rejected, nil
	}
	delete(s.posts, payload.PostID)
	return nil, nil
}

func (s *fakeSocialMediaService) post(postID string) (socialPost, bool) {
	post, ok := s.posts[postID]
	return post, ok
}

func socialReject(reason string) domain.VerificationResult {
	return domain.VerificationResult{Decision: domain.DecisionRejected, Reasons: []string{reason}}
}

func containsBannedContent(content string, bannedWords []string) bool {
	lowerContent := strings.ToLower(content)
	for _, bannedWord := range bannedWords {
		if strings.Contains(lowerContent, strings.ToLower(bannedWord)) {
			return true
		}
	}
	return false
}

func TestSocialDelegatedPublishAuthorized(t *testing.T) {
	issuedAt := time.Date(2026, 2, 12, 22, 15, 0, 0, time.UTC)
	ctx := buildSocialDelegationContext(t, socialDelegationContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(20 * time.Minute),
		AllowedActions: []string{"social:PublishPost"},
		Constraints:    defaultSocialConstraints(),
		NonceSeed:      0x71,
	})
	action := createSocialAction(t, ctx, socialActionInput{
		ActionTime: issuedAt.Add(1 * time.Minute),
		ActionType: "social:PublishPost",
		ActionPayload: `{
			"post_id":"post_1001",
			"account_id":"ignyte-main",
			"content":"We shipped delegated authority verification today.",
			"visibility":"public"
		}`,
		Evidence: defaultSocialEvidence("social:publish", "prod", 1),
	})

	service := newFakeSocialMediaService(map[string]struct{}{})
	result, err := service.Execute(ctx.capability, action, ctx.issuerPublicKey, ctx.agentPublicKey)
	if err != nil {
		t.Fatalf("execute social publish: %v", err)
	}
	if result.Decision != domain.DecisionAuthorized {
		t.Fatalf("expected AUTHORIZED, got %s with reasons %v", result.Decision, result.Reasons)
	}
	post, ok := service.post("post_1001")
	if !ok || post.AccountID != "ignyte-main" {
		t.Fatalf("expected post_1001 persisted, found=%v post=%+v", ok, post)
	}
}

func TestSocialDelegatedRejectsBannedContent(t *testing.T) {
	issuedAt := time.Date(2026, 2, 12, 22, 25, 0, 0, time.UTC)
	ctx := buildSocialDelegationContext(t, socialDelegationContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(20 * time.Minute),
		AllowedActions: []string{"social:PublishPost"},
		Constraints:    defaultSocialConstraints(),
		NonceSeed:      0x72,
	})
	action := createSocialAction(t, ctx, socialActionInput{
		ActionTime: issuedAt.Add(1 * time.Minute),
		ActionType: "social:PublishPost",
		ActionPayload: `{
			"post_id":"post_1002",
			"account_id":"ignyte-main",
			"content":"This is a leak of unreleased plans.",
			"visibility":"public"
		}`,
		Evidence: defaultSocialEvidence("social:publish", "prod", 1),
	})

	service := newFakeSocialMediaService(map[string]struct{}{})
	result, err := service.Execute(ctx.capability, action, ctx.issuerPublicKey, ctx.agentPublicKey)
	if err != nil {
		t.Fatalf("execute moderated social publish: %v", err)
	}
	if result.Decision != domain.DecisionRejected {
		t.Fatalf("expected REJECTED, got %s", result.Decision)
	}
	if !hasReasonFragment(result.Reasons, "content failed moderation") {
		t.Fatalf("expected moderation rejection, got %v", result.Reasons)
	}
}

func TestSocialDelegatedRejectsContentTooLong(t *testing.T) {
	issuedAt := time.Date(2026, 2, 12, 22, 35, 0, 0, time.UTC)
	ctx := buildSocialDelegationContext(t, socialDelegationContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(20 * time.Minute),
		AllowedActions: []string{"social:PublishPost"},
		Constraints:    defaultSocialConstraints(),
		NonceSeed:      0x73,
	})
	longContent := strings.Repeat("a", 281)
	action := createSocialAction(t, ctx, socialActionInput{
		ActionTime: issuedAt.Add(1 * time.Minute),
		ActionType: "social:PublishPost",
		ActionPayload: fmt.Sprintf(`{
			"post_id":"post_1003",
			"account_id":"ignyte-main",
			"content":"%s",
			"visibility":"public"
		}`, longContent),
		Evidence: defaultSocialEvidence("social:publish", "prod", 1),
	})

	service := newFakeSocialMediaService(map[string]struct{}{})
	result, err := service.Execute(ctx.capability, action, ctx.issuerPublicKey, ctx.agentPublicKey)
	if err != nil {
		t.Fatalf("execute oversized social publish: %v", err)
	}
	if result.Decision != domain.DecisionRejected {
		t.Fatalf("expected REJECTED, got %s", result.Decision)
	}
	if !hasReasonFragment(result.Reasons, "content exceeds 280") {
		t.Fatalf("expected length rejection, got %v", result.Reasons)
	}
}

func TestSocialDelegatedRejectsUnknownAccount(t *testing.T) {
	issuedAt := time.Date(2026, 2, 12, 22, 45, 0, 0, time.UTC)
	ctx := buildSocialDelegationContext(t, socialDelegationContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(20 * time.Minute),
		AllowedActions: []string{"social:PublishPost"},
		Constraints:    defaultSocialConstraints(),
		NonceSeed:      0x74,
	})
	action := createSocialAction(t, ctx, socialActionInput{
		ActionTime: issuedAt.Add(1 * time.Minute),
		ActionType: "social:PublishPost",
		ActionPayload: `{
			"post_id":"post_1004",
			"account_id":"unknown-account",
			"content":"Status update",
			"visibility":"public"
		}`,
		Evidence: defaultSocialEvidence("social:publish", "prod", 1),
	})

	service := newFakeSocialMediaService(map[string]struct{}{})
	result, err := service.Execute(ctx.capability, action, ctx.issuerPublicKey, ctx.agentPublicKey)
	if err != nil {
		t.Fatalf("execute unknown-account social publish: %v", err)
	}
	if result.Decision != domain.DecisionRejected {
		t.Fatalf("expected REJECTED, got %s", result.Decision)
	}
	if !hasReasonFragment(result.Reasons, "account_id is not authorized") {
		t.Fatalf("expected account rejection, got %v", result.Reasons)
	}
}

func TestSocialDelegatedDeleteAuthorized(t *testing.T) {
	issuedAt := time.Date(2026, 2, 12, 22, 55, 0, 0, time.UTC)
	ctx := buildSocialDelegationContext(t, socialDelegationContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(25 * time.Minute),
		AllowedActions: []string{"social:PublishPost", "social:DeletePost"},
		Constraints:    defaultSocialConstraints(),
		NonceSeed:      0x75,
	})
	publish := createSocialAction(t, ctx, socialActionInput{
		ActionTime: issuedAt.Add(1 * time.Minute),
		ActionType: "social:PublishPost",
		ActionPayload: `{
			"post_id":"post_1005",
			"account_id":"ignyte-main",
			"content":"Temporary announcement",
			"visibility":"public"
		}`,
		Evidence: defaultSocialEvidence("social:publish", "prod", 1),
	})
	deleteAction := createSocialAction(t, ctx, socialActionInput{
		ActionTime: issuedAt.Add(2 * time.Minute),
		ActionType: "social:DeletePost",
		ActionPayload: `{
			"post_id":"post_1005",
			"account_id":"ignyte-main"
		}`,
		Evidence: defaultSocialEvidence("social:publish", "prod", 1),
	})

	service := newFakeSocialMediaService(map[string]struct{}{})
	publishResult, err := service.Execute(ctx.capability, publish, ctx.issuerPublicKey, ctx.agentPublicKey)
	if err != nil {
		t.Fatalf("execute social publish before delete: %v", err)
	}
	if publishResult.Decision != domain.DecisionAuthorized {
		t.Fatalf("expected publish AUTHORIZED, got %s", publishResult.Decision)
	}
	deleteResult, err := service.Execute(ctx.capability, deleteAction, ctx.issuerPublicKey, ctx.agentPublicKey)
	if err != nil {
		t.Fatalf("execute social delete: %v", err)
	}
	if deleteResult.Decision != domain.DecisionAuthorized {
		t.Fatalf("expected delete AUTHORIZED, got %s", deleteResult.Decision)
	}
	if _, exists := service.post("post_1005"); exists {
		t.Fatal("expected post_1005 to be deleted")
	}
}

func TestSocialDelegatedRejectsDeleteOutsideCapability(t *testing.T) {
	issuedAt := time.Date(2026, 2, 12, 23, 5, 0, 0, time.UTC)
	ctx := buildSocialDelegationContext(t, socialDelegationContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(20 * time.Minute),
		AllowedActions: []string{"social:PublishPost"},
		Constraints:    defaultSocialConstraints(),
		NonceSeed:      0x76,
	})
	deleteAction := createSocialAction(t, ctx, socialActionInput{
		ActionTime: issuedAt.Add(1 * time.Minute),
		ActionType: "social:DeletePost",
		ActionPayload: `{
			"post_id":"post_1006",
			"account_id":"ignyte-main"
		}`,
		Evidence: defaultSocialEvidence("social:publish", "prod", 1),
	})

	service := newFakeSocialMediaService(map[string]struct{}{})
	result, err := service.Execute(ctx.capability, deleteAction, ctx.issuerPublicKey, ctx.agentPublicKey)
	if err != nil {
		t.Fatalf("execute unauthorized social delete: %v", err)
	}
	if result.Decision != domain.DecisionRejected {
		t.Fatalf("expected REJECTED, got %s", result.Decision)
	}
	if !hasReasonFragment(result.Reasons, "action_type is not allowed") {
		t.Fatalf("expected action-type rejection, got %v", result.Reasons)
	}
}

func TestSocialDelegatedRejectsReplayActionEnvelope(t *testing.T) {
	issuedAt := time.Date(2026, 2, 12, 23, 15, 0, 0, time.UTC)
	ctx := buildSocialDelegationContext(t, socialDelegationContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(20 * time.Minute),
		AllowedActions: []string{"social:PublishPost"},
		Constraints:    defaultSocialConstraints(),
		NonceSeed:      0x77,
	})
	action := createSocialAction(t, ctx, socialActionInput{
		ActionTime: issuedAt.Add(1 * time.Minute),
		ActionType: "social:PublishPost",
		ActionPayload: `{
			"post_id":"post_1007",
			"account_id":"ignyte-main",
			"content":"Replay test",
			"visibility":"public"
		}`,
		Evidence: defaultSocialEvidence("social:publish", "prod", 1),
	})

	service := newFakeSocialMediaService(map[string]struct{}{})
	first, err := service.Execute(ctx.capability, action, ctx.issuerPublicKey, ctx.agentPublicKey)
	if err != nil {
		t.Fatalf("execute first social post: %v", err)
	}
	if first.Decision != domain.DecisionAuthorized {
		t.Fatalf("expected first AUTHORIZED, got %s", first.Decision)
	}
	second, err := service.Execute(ctx.capability, action, ctx.issuerPublicKey, ctx.agentPublicKey)
	if err != nil {
		t.Fatalf("execute replay social post: %v", err)
	}
	if second.Decision != domain.DecisionRejected {
		t.Fatalf("expected replay REJECTED, got %s", second.Decision)
	}
	if !hasReasonFragment(second.Reasons, "replay detected") {
		t.Fatalf("expected replay reason, got %v", second.Reasons)
	}
}

func TestSocialDelegatedRejectsScopeMismatch(t *testing.T) {
	issuedAt := time.Date(2026, 2, 12, 23, 25, 0, 0, time.UTC)
	ctx := buildSocialDelegationContext(t, socialDelegationContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(20 * time.Minute),
		AllowedActions: []string{"social:PublishPost"},
		Constraints:    defaultSocialConstraints(),
		NonceSeed:      0x78,
	})
	action := createSocialAction(t, ctx, socialActionInput{
		ActionTime: issuedAt.Add(1 * time.Minute),
		ActionType: "social:PublishPost",
		ActionPayload: `{
			"post_id":"post_1008",
			"account_id":"ignyte-main",
			"content":"Scope mismatch test",
			"visibility":"public"
		}`,
		Evidence: defaultSocialEvidence("social:admin", "prod", 1),
	})

	service := newFakeSocialMediaService(map[string]struct{}{})
	result, err := service.Execute(ctx.capability, action, ctx.issuerPublicKey, ctx.agentPublicKey)
	if err != nil {
		t.Fatalf("execute scope mismatch social post: %v", err)
	}
	if result.Decision != domain.DecisionRejected {
		t.Fatalf("expected REJECTED, got %s", result.Decision)
	}
	if !hasReasonFragment(result.Reasons, "api_scope is not allowed") {
		t.Fatalf("expected scope rejection reason, got %v", result.Reasons)
	}
}

type socialDelegationContext struct {
	capability      domain.Capability
	issuerPublicKey string
	agentPublicKey  string
	agentPrivateKey ed25519.PrivateKey
}

type socialDelegationContextInput struct {
	IssuedAt       time.Time
	ExpiresAt      time.Time
	AllowedActions []string
	Constraints    domain.CapabilityConstraints
	NonceSeed      byte
}

type socialActionInput struct {
	ActionTime    time.Time
	ActionType    string
	ActionPayload string
	Evidence      domain.ConstraintEvidence
}

func buildSocialDelegationContext(t *testing.T, input socialDelegationContextInput) socialDelegationContext {
	t.Helper()
	issuerPublicKey, issuerPrivateKey, err := anchorcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate issuer key pair: %v", err)
	}
	agentPublicKey, agentPrivateKey, err := anchorcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate agent key pair: %v", err)
	}

	issuerService, err := issuer.NewService(issuerPrivateKey, bytes.NewReader(bytes.Repeat([]byte{input.NonceSeed}, 32)), socialClock{now: input.IssuedAt})
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
		t.Fatalf("issue social capability: %v", err)
	}

	return socialDelegationContext{
		capability:      capabilityToken,
		issuerPublicKey: anchorcrypto.PublicKeyToBase64(issuerPublicKey),
		agentPublicKey:  anchorcrypto.PublicKeyToBase64(agentPublicKey),
		agentPrivateKey: agentPrivateKey,
	}
}

func createSocialAction(t *testing.T, ctx socialDelegationContext, input socialActionInput) domain.ActionEnvelope {
	t.Helper()
	agentRuntime, err := runtime.New(ctx.agentPrivateKey, socialClock{now: input.ActionTime})
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
		t.Fatalf("create social action: %v", err)
	}
	return action
}

func defaultSocialConstraints() domain.CapabilityConstraints {
	return domain.CapabilityConstraints{
		ResourceLimits:         map[string]int64{"social:posts": 5},
		SpendLimits:            map[string]int64{"usd_cents": 500},
		APIScopes:              []string{"social:publish"},
		RateLimits:             map[string]int64{"requests_per_minute": 10},
		EnvironmentConstraints: []string{"prod"},
	}
}

func defaultSocialEvidence(scope, environment string, postUsage int64) domain.ConstraintEvidence {
	return domain.ConstraintEvidence{
		ResourceUsage: map[string]int64{"social:posts": postUsage},
		SpendUsage:    map[string]int64{"usd_cents": 20},
		RateUsage:     map[string]int64{"requests_per_minute": 1},
		Environment:   environment,
		APIScope:      scope,
	}
}
