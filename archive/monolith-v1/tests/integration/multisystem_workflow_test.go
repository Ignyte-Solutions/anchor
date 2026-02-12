package integration_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/ignyte-solutions/ignyte-anchor/internal/domain"
	"github.com/ignyte-solutions/ignyte-anchor/internal/runtime"
)

func TestMultiSystemReleaseWorkflowAuthorized(t *testing.T) {
	issuedAt := time.Date(2026, 2, 13, 1, 0, 0, 0, time.UTC)

	awsCtx := buildAWSDelegationContext(t, awsDelegationContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(30 * time.Minute),
		AllowedActions: []string{"s3:PutObject"},
		Constraints:    defaultAWSConstraints("aws:s3"),
		NonceSeed:      0x91,
	})
	socialCtx := buildSocialDelegationContext(t, socialDelegationContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(30 * time.Minute),
		AllowedActions: []string{"social:PublishPost"},
		Constraints:    defaultSocialConstraints(),
		NonceSeed:      0x92,
	})
	bankCtx := buildBankDelegationContext(t, bankDelegationContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(30 * time.Minute),
		AllowedActions: []string{"bank:TransferFunds"},
		Constraints:    defaultBankConstraints(),
		NonceSeed:      0x93,
	})

	awsAction := createAWSAction(t, awsCtx, awsActionInput{
		ActionTime: issuedAt.Add(1 * time.Minute),
		ActionType: "s3:PutObject",
		ActionPayload: `{
			"bucket":"release-artifacts",
			"key":"v2.1.0/manifest.json",
			"body":"{\"version\":\"2.1.0\"}",
			"region":"us-east-1"
		}`,
		Evidence: defaultAWSEvidence("aws:s3", "prod"),
	})
	socialAction := createSocialAction(t, socialCtx, socialActionInput{
		ActionTime: issuedAt.Add(2 * time.Minute),
		ActionType: "social:PublishPost",
		ActionPayload: `{
			"post_id":"campaign_2001",
			"account_id":"ignyte-main",
			"content":"Ignyte Anchor v2.1.0 is live with stronger delegated controls.",
			"visibility":"public"
		}`,
		Evidence: defaultSocialEvidence("social:publish", "prod", 1),
	})
	bankAction := createBankTransferAction(t, bankCtx, bankActionInput{
		ActionTime:    issuedAt.Add(3 * time.Minute),
		TransferID:    "tr_release_2001",
		FromAccount:   "operating",
		ToAccount:     "contractor",
		AmountCents:   4200,
		Reference:     "release-bonus",
		Scope:         "bank:payments",
		Environment:   "prod",
		ResourceUsage: 1,
		SpendUsage:    4200,
		RateUsage:     1,
	})

	awsService := newFakeAWSService()
	socialService := newFakeSocialMediaService(map[string]struct{}{})
	bankService := newFakeBankService(map[string]int64{"operating": 100_000, "contractor": 0}, map[string]struct{}{}, 30_000)

	awsResult, err := awsService.Execute(awsCtx.capability, awsAction, awsCtx.issuerPublicKey, awsCtx.agentPublicKey)
	if err != nil {
		t.Fatalf("aws workflow step failed: %v", err)
	}
	socialResult, err := socialService.Execute(socialCtx.capability, socialAction, socialCtx.issuerPublicKey, socialCtx.agentPublicKey)
	if err != nil {
		t.Fatalf("social workflow step failed: %v", err)
	}
	bankResult, err := bankService.Execute(bankCtx.capability, bankAction, bankCtx.issuerPublicKey, bankCtx.agentPublicKey)
	if err != nil {
		t.Fatalf("bank workflow step failed: %v", err)
	}

	if awsResult.Decision != domain.DecisionAuthorized || socialResult.Decision != domain.DecisionAuthorized || bankResult.Decision != domain.DecisionAuthorized {
		t.Fatalf("expected all workflow steps authorized; aws=%s social=%s bank=%s", awsResult.Decision, socialResult.Decision, bankResult.Decision)
	}
	if _, ok := awsService.object("release-artifacts", "v2.1.0/manifest.json"); !ok {
		t.Fatal("expected aws artifact to be uploaded")
	}
	if _, ok := socialService.post("campaign_2001"); !ok {
		t.Fatal("expected social campaign post to be published")
	}
	if bankService.balance("contractor") != 4200 {
		t.Fatalf("expected contractor payout to be recorded, got %d", bankService.balance("contractor"))
	}
}

func TestMultiSystemMixedOutcomesIsolation(t *testing.T) {
	issuedAt := time.Date(2026, 2, 13, 1, 20, 0, 0, time.UTC)

	awsCtx := buildAWSDelegationContext(t, awsDelegationContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(30 * time.Minute),
		AllowedActions: []string{"s3:PutObject"},
		Constraints:    defaultAWSConstraints("aws:s3"),
		NonceSeed:      0x94,
	})
	socialCtx := buildSocialDelegationContext(t, socialDelegationContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(30 * time.Minute),
		AllowedActions: []string{"social:PublishPost"},
		Constraints:    defaultSocialConstraints(),
		NonceSeed:      0x95,
	})
	bankCtx := buildBankDelegationContext(t, bankDelegationContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(30 * time.Minute),
		AllowedActions: []string{"bank:TransferFunds"},
		Constraints:    defaultBankConstraints(),
		NonceSeed:      0x96,
	})

	awsAction := createAWSAction(t, awsCtx, awsActionInput{
		ActionTime: issuedAt.Add(1 * time.Minute),
		ActionType: "s3:PutObject",
		ActionPayload: `{
			"bucket":"release-artifacts",
			"key":"v2.1.1/manifest.json",
			"body":"{\"version\":\"2.1.1\"}",
			"region":"us-east-1"
		}`,
		Evidence: defaultAWSEvidence("aws:s3", "prod"),
	})
	socialAction := createSocialAction(t, socialCtx, socialActionInput{
		ActionTime: issuedAt.Add(2 * time.Minute),
		ActionType: "social:PublishPost",
		ActionPayload: `{
			"post_id":"campaign_2002",
			"account_id":"ignyte-main",
			"content":"This release is a leak of unreleased plans.",
			"visibility":"public"
		}`,
		Evidence: defaultSocialEvidence("social:publish", "prod", 1),
	})
	bankAction := createBankTransferAction(t, bankCtx, bankActionInput{
		ActionTime:    issuedAt.Add(3 * time.Minute),
		TransferID:    "tr_release_2002",
		FromAccount:   "operating",
		ToAccount:     "contractor",
		AmountCents:   1800,
		Reference:     "maintenance-bonus",
		Scope:         "bank:payments",
		Environment:   "prod",
		ResourceUsage: 1,
		SpendUsage:    1800,
		RateUsage:     1,
	})

	awsService := newFakeAWSService()
	socialService := newFakeSocialMediaService(map[string]struct{}{})
	bankService := newFakeBankService(map[string]int64{"operating": 100_000, "contractor": 0}, map[string]struct{}{}, 30_000)

	awsResult, err := awsService.Execute(awsCtx.capability, awsAction, awsCtx.issuerPublicKey, awsCtx.agentPublicKey)
	if err != nil {
		t.Fatalf("aws step failed: %v", err)
	}
	socialResult, err := socialService.Execute(socialCtx.capability, socialAction, socialCtx.issuerPublicKey, socialCtx.agentPublicKey)
	if err != nil {
		t.Fatalf("social step failed: %v", err)
	}
	bankResult, err := bankService.Execute(bankCtx.capability, bankAction, bankCtx.issuerPublicKey, bankCtx.agentPublicKey)
	if err != nil {
		t.Fatalf("bank step failed: %v", err)
	}

	if awsResult.Decision != domain.DecisionAuthorized {
		t.Fatalf("expected aws authorized, got %s", awsResult.Decision)
	}
	if socialResult.Decision != domain.DecisionRejected {
		t.Fatalf("expected social rejected, got %s", socialResult.Decision)
	}
	if !hasReasonFragment(socialResult.Reasons, "content failed moderation") {
		t.Fatalf("expected social moderation rejection, got %v", socialResult.Reasons)
	}
	if bankResult.Decision != domain.DecisionAuthorized {
		t.Fatalf("expected bank authorized, got %s", bankResult.Decision)
	}
	if _, ok := socialService.post("campaign_2002"); ok {
		t.Fatal("expected moderated post not to persist")
	}
	if bankService.balance("contractor") != 1800 {
		t.Fatalf("expected bank payout to still execute, got %d", bankService.balance("contractor"))
	}
}

func TestMultiSystemCrossCapabilityMisuseRejected(t *testing.T) {
	issuedAt := time.Date(2026, 2, 13, 1, 40, 0, 0, time.UTC)

	bankCtx := buildBankDelegationContext(t, bankDelegationContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(30 * time.Minute),
		AllowedActions: []string{"bank:TransferFunds"},
		Constraints:    defaultBankConstraints(),
		NonceSeed:      0x97,
	})
	bankAgentRuntime, err := runtime.New(bankCtx.agentPrivateKey, bankClock{now: issuedAt.Add(1 * time.Minute)})
	if err != nil {
		t.Fatalf("create bank runtime: %v", err)
	}
	misusedAction, err := bankAgentRuntime.CreateActionEnvelope(runtime.ActionRequest{
		CapabilityID: bankCtx.capability.CapabilityID,
		ActionType:   "social:PublishPost",
		ActionPayload: json.RawMessage(`{
			"post_id":"campaign_misuse",
			"account_id":"ignyte-main",
			"content":"Should not be allowed with bank capability.",
			"visibility":"public"
		}`),
		ConstraintEvidence: domain.ConstraintEvidence{
			ResourceUsage: map[string]int64{"bank:transfers": 1},
			SpendUsage:    map[string]int64{"usd_cents": 100},
			RateUsage:     map[string]int64{"requests_per_minute": 1},
			Environment:   "prod",
			APIScope:      "bank:payments",
		},
	})
	if err != nil {
		t.Fatalf("create misused action: %v", err)
	}

	socialService := newFakeSocialMediaService(map[string]struct{}{})
	result, err := socialService.Execute(bankCtx.capability, misusedAction, bankCtx.issuerPublicKey, bankCtx.agentPublicKey)
	if err != nil {
		t.Fatalf("execute misused cross-capability action: %v", err)
	}
	if result.Decision != domain.DecisionRejected {
		t.Fatalf("expected REJECTED for cross-capability misuse, got %s", result.Decision)
	}
	if !hasReasonFragment(result.Reasons, "action_type is not allowed") {
		t.Fatalf("expected action_type rejection for misuse, got %v", result.Reasons)
	}
	if _, exists := socialService.post("campaign_misuse"); exists {
		t.Fatal("expected no social post persisted from misused capability")
	}
}
