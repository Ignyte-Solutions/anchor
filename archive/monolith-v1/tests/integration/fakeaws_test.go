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

type awsClock struct {
	now time.Time
}

func (c awsClock) Now() time.Time {
	return c.now
}

type fakeS3Object struct {
	Body   string
	Region string
}

type fakeAWSService struct {
	verifier          *verifier.Engine
	revoked           map[string]struct{}
	objects           map[string]fakeS3Object
	lambdaInvocations map[string]int
	processedActions  map[string]struct{}
}

func newFakeAWSService() *fakeAWSService {
	return newFakeAWSServiceWithRevocations(map[string]struct{}{})
}

func newFakeAWSServiceWithRevocations(revoked map[string]struct{}) *fakeAWSService {
	copyRevoked := make(map[string]struct{}, len(revoked))
	for id := range revoked {
		copyRevoked[id] = struct{}{}
	}
	return &fakeAWSService{
		verifier:          verifier.New(),
		revoked:           copyRevoked,
		objects:           map[string]fakeS3Object{},
		lambdaInvocations: map[string]int{},
		processedActions:  map[string]struct{}{},
	}
}

func (s *fakeAWSService) Execute(
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
		return reject("replay detected for action_id"), nil
	}

	switch actionEnvelope.ActionType {
	case "s3:PutObject":
		if rejectResult, rejectErr := s.executeS3PutObject(actionEnvelope); rejectErr != nil {
			return domain.VerificationResult{}, rejectErr
		} else if rejectResult != nil {
			return *rejectResult, nil
		}
	case "lambda:InvokeFunction":
		if rejectResult, rejectErr := s.executeLambdaInvoke(actionEnvelope); rejectErr != nil {
			return domain.VerificationResult{}, rejectErr
		} else if rejectResult != nil {
			return *rejectResult, nil
		}
	default:
		return reject("fake aws service does not implement this action"), nil
	}

	s.processedActions[actionEnvelope.ActionID] = struct{}{}
	return result, nil
}

func (s *fakeAWSService) executeS3PutObject(actionEnvelope domain.ActionEnvelope) (*domain.VerificationResult, error) {
	var payload struct {
		Bucket string `json:"bucket"`
		Key    string `json:"key"`
		Body   string `json:"body"`
		Region string `json:"region"`
	}
	if err := json.Unmarshal(actionEnvelope.ActionPayload, &payload); err != nil {
		return nil, fmt.Errorf("parse s3 payload: %w", err)
	}
	if payload.Bucket == "" || payload.Key == "" {
		rejected := reject("bucket and key are required")
		return &rejected, nil
	}
	if !isSupportedAWSRegion(payload.Region) {
		rejected := reject("unsupported aws region")
		return &rejected, nil
	}
	objectKey := payload.Bucket + "/" + payload.Key
	s.objects[objectKey] = fakeS3Object{Body: payload.Body, Region: payload.Region}
	return nil, nil
}

func (s *fakeAWSService) executeLambdaInvoke(actionEnvelope domain.ActionEnvelope) (*domain.VerificationResult, error) {
	var payload struct {
		FunctionName string          `json:"function_name"`
		Region       string          `json:"region"`
		Payload      json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(actionEnvelope.ActionPayload, &payload); err != nil {
		return nil, fmt.Errorf("parse lambda payload: %w", err)
	}
	if payload.FunctionName == "" {
		rejected := reject("function_name is required")
		return &rejected, nil
	}
	if !strings.HasPrefix(payload.FunctionName, "release-") {
		rejected := reject("function_name must start with release-")
		return &rejected, nil
	}
	if !isSupportedAWSRegion(payload.Region) {
		rejected := reject("unsupported aws region")
		return &rejected, nil
	}
	s.lambdaInvocations[payload.FunctionName] = s.lambdaInvocations[payload.FunctionName] + 1
	return nil, nil
}

func (s *fakeAWSService) object(bucket, key string) (fakeS3Object, bool) {
	value, ok := s.objects[bucket+"/"+key]
	return value, ok
}

func (s *fakeAWSService) lambdaInvocationCount(functionName string) int {
	return s.lambdaInvocations[functionName]
}

func isSupportedAWSRegion(region string) bool {
	supported := map[string]struct{}{
		"us-east-1": {},
		"us-west-2": {},
	}
	_, ok := supported[region]
	return ok
}

func TestAWSDelegatedS3PutObjectAuthorized(t *testing.T) {
	issuedAt := time.Date(2026, 2, 12, 18, 0, 0, 0, time.UTC)
	ctx := buildAWSDelegationContext(t, awsDelegationContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(20 * time.Minute),
		AllowedActions: []string{"s3:PutObject"},
		Constraints: domain.CapabilityConstraints{
			ResourceLimits:         map[string]int64{"s3:objects": 2},
			SpendLimits:            map[string]int64{"usd_cents": 500},
			APIScopes:              []string{"aws:s3"},
			RateLimits:             map[string]int64{"requests_per_minute": 5},
			EnvironmentConstraints: []string{"prod"},
		},
		NonceSeed: 0x51,
	})
	action := createAWSAction(t, ctx, awsActionInput{
		ActionTime: issuedAt.Add(2 * time.Minute),
		ActionType: "s3:PutObject",
		ActionPayload: `{
			"bucket":"project-artifacts",
			"key":"release-2026-02-12.txt",
			"body":"v2.0.0",
			"region":"us-east-1"
		}`,
		Evidence: domain.ConstraintEvidence{
			ResourceUsage: map[string]int64{"s3:objects": 1},
			SpendUsage:    map[string]int64{"usd_cents": 20},
			RateUsage:     map[string]int64{"requests_per_minute": 1},
			Environment:   "prod",
			APIScope:      "aws:s3",
		},
	})

	service := newFakeAWSService()
	result, err := service.Execute(ctx.capability, action, ctx.issuerPublicKey, ctx.agentPublicKey)
	if err != nil {
		t.Fatalf("execute delegated s3 put object: %v", err)
	}
	if result.Decision != domain.DecisionAuthorized {
		t.Fatalf("expected AUTHORIZED, got %s with reasons %v", result.Decision, result.Reasons)
	}
	stored, ok := service.object("project-artifacts", "release-2026-02-12.txt")
	if !ok || stored.Body != "v2.0.0" || stored.Region != "us-east-1" {
		t.Fatalf("expected object stored in us-east-1, found=%v object=%+v", ok, stored)
	}
}

func TestAWSDelegatedRejectsActionOutsideCapability(t *testing.T) {
	issuedAt := time.Date(2026, 2, 12, 18, 30, 0, 0, time.UTC)
	ctx := buildAWSDelegationContext(t, awsDelegationContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(30 * time.Minute),
		AllowedActions: []string{"s3:PutObject"},
		Constraints:    defaultAWSConstraints("aws:s3"),
		NonceSeed:      0x52,
	})
	action := createAWSAction(t, ctx, awsActionInput{
		ActionTime: issuedAt.Add(5 * time.Minute),
		ActionType: "ec2:TerminateInstances",
		ActionPayload: `{
			"instance_id":"i-0123456789"
		}`,
		Evidence: defaultAWSEvidence("aws:s3", "prod"),
	})

	service := newFakeAWSService()
	result, err := service.Execute(ctx.capability, action, ctx.issuerPublicKey, ctx.agentPublicKey)
	if err != nil {
		t.Fatalf("execute unauthorized aws action: %v", err)
	}
	if result.Decision != domain.DecisionRejected {
		t.Fatalf("expected REJECTED, got %s", result.Decision)
	}
	if !hasReasonFragment(result.Reasons, "action_type is not allowed") {
		t.Fatalf("expected action_type rejection, got %v", result.Reasons)
	}
}

func TestAWSDelegatedRejectsVerifierResourceLimitExceeded(t *testing.T) {
	issuedAt := time.Date(2026, 2, 12, 18, 45, 0, 0, time.UTC)
	ctx := buildAWSDelegationContext(t, awsDelegationContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(30 * time.Minute),
		AllowedActions: []string{"s3:PutObject"},
		Constraints: domain.CapabilityConstraints{
			ResourceLimits:         map[string]int64{"s3:objects": 1},
			SpendLimits:            map[string]int64{"usd_cents": 500},
			APIScopes:              []string{"aws:s3"},
			RateLimits:             map[string]int64{"requests_per_minute": 5},
			EnvironmentConstraints: []string{"prod"},
		},
		NonceSeed: 0x53,
	})
	action := createAWSAction(t, ctx, awsActionInput{
		ActionTime: issuedAt.Add(2 * time.Minute),
		ActionType: "s3:PutObject",
		ActionPayload: `{
			"bucket":"project-artifacts",
			"key":"over-limit.txt",
			"body":"x",
			"region":"us-east-1"
		}`,
		Evidence: domain.ConstraintEvidence{
			ResourceUsage: map[string]int64{"s3:objects": 2},
			SpendUsage:    map[string]int64{"usd_cents": 10},
			RateUsage:     map[string]int64{"requests_per_minute": 1},
			Environment:   "prod",
			APIScope:      "aws:s3",
		},
	})

	service := newFakeAWSService()
	result, err := service.Execute(ctx.capability, action, ctx.issuerPublicKey, ctx.agentPublicKey)
	if err != nil {
		t.Fatalf("execute over-limit aws action: %v", err)
	}
	if result.Decision != domain.DecisionRejected {
		t.Fatalf("expected REJECTED, got %s", result.Decision)
	}
	if !hasReasonFragment(result.Reasons, "resource usage for s3:objects exceeds limit") {
		t.Fatalf("expected resource-limit rejection, got %v", result.Reasons)
	}
}

func TestAWSDelegatedRejectsVerifierEnvironmentMismatch(t *testing.T) {
	issuedAt := time.Date(2026, 2, 12, 19, 0, 0, 0, time.UTC)
	ctx := buildAWSDelegationContext(t, awsDelegationContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(30 * time.Minute),
		AllowedActions: []string{"s3:PutObject"},
		Constraints:    defaultAWSConstraints("aws:s3"),
		NonceSeed:      0x54,
	})
	action := createAWSAction(t, ctx, awsActionInput{
		ActionTime: issuedAt.Add(2 * time.Minute),
		ActionType: "s3:PutObject",
		ActionPayload: `{
			"bucket":"project-artifacts",
			"key":"staging.txt",
			"body":"hello",
			"region":"us-east-1"
		}`,
		Evidence: defaultAWSEvidence("aws:s3", "staging"),
	})

	service := newFakeAWSService()
	result, err := service.Execute(ctx.capability, action, ctx.issuerPublicKey, ctx.agentPublicKey)
	if err != nil {
		t.Fatalf("execute env-mismatch aws action: %v", err)
	}
	if result.Decision != domain.DecisionRejected {
		t.Fatalf("expected REJECTED, got %s", result.Decision)
	}
	if !hasReasonFragment(result.Reasons, "environment is not allowed") {
		t.Fatalf("expected environment rejection, got %v", result.Reasons)
	}
}

func TestAWSDelegatedRejectsReplayActionEnvelope(t *testing.T) {
	issuedAt := time.Date(2026, 2, 12, 19, 15, 0, 0, time.UTC)
	ctx := buildAWSDelegationContext(t, awsDelegationContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(20 * time.Minute),
		AllowedActions: []string{"s3:PutObject"},
		Constraints:    defaultAWSConstraints("aws:s3"),
		NonceSeed:      0x55,
	})
	action := createAWSAction(t, ctx, awsActionInput{
		ActionTime: issuedAt.Add(2 * time.Minute),
		ActionType: "s3:PutObject",
		ActionPayload: `{
			"bucket":"project-artifacts",
			"key":"idempotency.txt",
			"body":"hello",
			"region":"us-east-1"
		}`,
		Evidence: defaultAWSEvidence("aws:s3", "prod"),
	})

	service := newFakeAWSService()
	first, err := service.Execute(ctx.capability, action, ctx.issuerPublicKey, ctx.agentPublicKey)
	if err != nil {
		t.Fatalf("execute initial aws action: %v", err)
	}
	if first.Decision != domain.DecisionAuthorized {
		t.Fatalf("expected first action AUTHORIZED, got %s", first.Decision)
	}

	second, err := service.Execute(ctx.capability, action, ctx.issuerPublicKey, ctx.agentPublicKey)
	if err != nil {
		t.Fatalf("execute replay aws action: %v", err)
	}
	if second.Decision != domain.DecisionRejected {
		t.Fatalf("expected replay REJECTED, got %s", second.Decision)
	}
	if !hasReasonFragment(second.Reasons, "replay detected") {
		t.Fatalf("expected replay rejection, got %v", second.Reasons)
	}
}

func TestAWSDelegatedLambdaInvokeAuthorized(t *testing.T) {
	issuedAt := time.Date(2026, 2, 12, 19, 30, 0, 0, time.UTC)
	ctx := buildAWSDelegationContext(t, awsDelegationContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(20 * time.Minute),
		AllowedActions: []string{"lambda:InvokeFunction"},
		Constraints: domain.CapabilityConstraints{
			ResourceLimits:         map[string]int64{"lambda:invocations": 2},
			SpendLimits:            map[string]int64{"usd_cents": 200},
			APIScopes:              []string{"aws:lambda"},
			RateLimits:             map[string]int64{"requests_per_minute": 5},
			EnvironmentConstraints: []string{"prod"},
		},
		NonceSeed: 0x56,
	})
	action := createAWSAction(t, ctx, awsActionInput{
		ActionTime: issuedAt.Add(1 * time.Minute),
		ActionType: "lambda:InvokeFunction",
		ActionPayload: `{
			"function_name":"release-indexer",
			"region":"us-east-1",
			"payload":{"build_id":"b-123"}
		}`,
		Evidence: domain.ConstraintEvidence{
			ResourceUsage: map[string]int64{"lambda:invocations": 1},
			SpendUsage:    map[string]int64{"usd_cents": 15},
			RateUsage:     map[string]int64{"requests_per_minute": 1},
			Environment:   "prod",
			APIScope:      "aws:lambda",
		},
	})

	service := newFakeAWSService()
	result, err := service.Execute(ctx.capability, action, ctx.issuerPublicKey, ctx.agentPublicKey)
	if err != nil {
		t.Fatalf("execute lambda invoke: %v", err)
	}
	if result.Decision != domain.DecisionAuthorized {
		t.Fatalf("expected AUTHORIZED, got %s with reasons %v", result.Decision, result.Reasons)
	}
	if count := service.lambdaInvocationCount("release-indexer"); count != 1 {
		t.Fatalf("expected 1 invocation for release-indexer, got %d", count)
	}
}

func TestAWSDelegatedLambdaRejectsWrongScope(t *testing.T) {
	issuedAt := time.Date(2026, 2, 12, 19, 45, 0, 0, time.UTC)
	ctx := buildAWSDelegationContext(t, awsDelegationContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(20 * time.Minute),
		AllowedActions: []string{"lambda:InvokeFunction"},
		Constraints: domain.CapabilityConstraints{
			ResourceLimits:         map[string]int64{"lambda:invocations": 2},
			SpendLimits:            map[string]int64{"usd_cents": 200},
			APIScopes:              []string{"aws:lambda"},
			RateLimits:             map[string]int64{"requests_per_minute": 5},
			EnvironmentConstraints: []string{"prod"},
		},
		NonceSeed: 0x57,
	})
	action := createAWSAction(t, ctx, awsActionInput{
		ActionTime: issuedAt.Add(1 * time.Minute),
		ActionType: "lambda:InvokeFunction",
		ActionPayload: `{
			"function_name":"release-indexer",
			"region":"us-east-1",
			"payload":{"build_id":"b-124"}
		}`,
		Evidence: domain.ConstraintEvidence{
			ResourceUsage: map[string]int64{"lambda:invocations": 1},
			SpendUsage:    map[string]int64{"usd_cents": 15},
			RateUsage:     map[string]int64{"requests_per_minute": 1},
			Environment:   "prod",
			APIScope:      "aws:s3",
		},
	})

	service := newFakeAWSService()
	result, err := service.Execute(ctx.capability, action, ctx.issuerPublicKey, ctx.agentPublicKey)
	if err != nil {
		t.Fatalf("execute lambda wrong-scope action: %v", err)
	}
	if result.Decision != domain.DecisionRejected {
		t.Fatalf("expected REJECTED, got %s", result.Decision)
	}
	if !hasReasonFragment(result.Reasons, "api_scope is not allowed") {
		t.Fatalf("expected api_scope rejection, got %v", result.Reasons)
	}
}

func TestAWSDelegatedRejectsUnsupportedRegionAtServiceLayer(t *testing.T) {
	issuedAt := time.Date(2026, 2, 12, 20, 0, 0, 0, time.UTC)
	ctx := buildAWSDelegationContext(t, awsDelegationContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(20 * time.Minute),
		AllowedActions: []string{"s3:PutObject"},
		Constraints:    defaultAWSConstraints("aws:s3"),
		NonceSeed:      0x58,
	})
	action := createAWSAction(t, ctx, awsActionInput{
		ActionTime: issuedAt.Add(1 * time.Minute),
		ActionType: "s3:PutObject",
		ActionPayload: `{
			"bucket":"project-artifacts",
			"key":"eu.txt",
			"body":"hello",
			"region":"eu-central-1"
		}`,
		Evidence: defaultAWSEvidence("aws:s3", "prod"),
	})

	service := newFakeAWSService()
	result, err := service.Execute(ctx.capability, action, ctx.issuerPublicKey, ctx.agentPublicKey)
	if err != nil {
		t.Fatalf("execute unsupported-region action: %v", err)
	}
	if result.Decision != domain.DecisionRejected {
		t.Fatalf("expected REJECTED, got %s", result.Decision)
	}
	if !hasReasonFragment(result.Reasons, "unsupported aws region") {
		t.Fatalf("expected region rejection, got %v", result.Reasons)
	}
}

func TestAWSDelegatedRejectsRevokedCapability(t *testing.T) {
	issuedAt := time.Date(2026, 2, 12, 20, 15, 0, 0, time.UTC)
	ctx := buildAWSDelegationContext(t, awsDelegationContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(20 * time.Minute),
		AllowedActions: []string{"s3:PutObject"},
		Constraints:    defaultAWSConstraints("aws:s3"),
		NonceSeed:      0x59,
	})
	action := createAWSAction(t, ctx, awsActionInput{
		ActionTime: issuedAt.Add(1 * time.Minute),
		ActionType: "s3:PutObject",
		ActionPayload: `{
			"bucket":"project-artifacts",
			"key":"revoked.txt",
			"body":"hello",
			"region":"us-east-1"
		}`,
		Evidence: defaultAWSEvidence("aws:s3", "prod"),
	})

	service := newFakeAWSServiceWithRevocations(map[string]struct{}{ctx.capability.CapabilityID: {}})
	result, err := service.Execute(ctx.capability, action, ctx.issuerPublicKey, ctx.agentPublicKey)
	if err != nil {
		t.Fatalf("execute revoked capability action: %v", err)
	}
	if result.Decision != domain.DecisionRejected {
		t.Fatalf("expected REJECTED, got %s", result.Decision)
	}
	if !hasReasonFragment(result.Reasons, "capability is revoked") {
		t.Fatalf("expected revoked rejection, got %v", result.Reasons)
	}
}

type awsDelegationContext struct {
	capability      domain.Capability
	issuerPublicKey string
	agentPublicKey  string
	agentPrivateKey ed25519.PrivateKey
}

type awsDelegationContextInput struct {
	IssuedAt       time.Time
	ExpiresAt      time.Time
	AllowedActions []string
	Constraints    domain.CapabilityConstraints
	NonceSeed      byte
}

type awsActionInput struct {
	ActionTime    time.Time
	ActionType    string
	ActionPayload string
	Evidence      domain.ConstraintEvidence
}

func buildAWSDelegationContext(t *testing.T, input awsDelegationContextInput) awsDelegationContext {
	t.Helper()
	issuerPublicKey, issuerPrivateKey, err := anchorcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate issuer key pair: %v", err)
	}
	agentPublicKey, agentPrivateKey, err := anchorcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate agent key pair: %v", err)
	}

	issuerService, err := issuer.NewService(issuerPrivateKey, bytes.NewReader(bytes.Repeat([]byte{input.NonceSeed}, 32)), awsClock{now: input.IssuedAt})
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
		t.Fatalf("issue capability: %v", err)
	}

	return awsDelegationContext{
		capability:      capabilityToken,
		issuerPublicKey: anchorcrypto.PublicKeyToBase64(issuerPublicKey),
		agentPublicKey:  anchorcrypto.PublicKeyToBase64(agentPublicKey),
		agentPrivateKey: agentPrivateKey,
	}
}

func createAWSAction(t *testing.T, ctx awsDelegationContext, input awsActionInput) domain.ActionEnvelope {
	t.Helper()
	agentRuntime, err := runtime.New(ctx.agentPrivateKey, awsClock{now: input.ActionTime})
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
		t.Fatalf("create action envelope: %v", err)
	}
	return action
}

func defaultAWSConstraints(scope string) domain.CapabilityConstraints {
	return domain.CapabilityConstraints{
		ResourceLimits:         map[string]int64{"s3:objects": 2, "lambda:invocations": 2},
		SpendLimits:            map[string]int64{"usd_cents": 500},
		APIScopes:              []string{scope},
		RateLimits:             map[string]int64{"requests_per_minute": 5},
		EnvironmentConstraints: []string{"prod"},
	}
}

func defaultAWSEvidence(scope, environment string) domain.ConstraintEvidence {
	return domain.ConstraintEvidence{
		ResourceUsage: map[string]int64{"s3:objects": 1},
		SpendUsage:    map[string]int64{"usd_cents": 20},
		RateUsage:     map[string]int64{"requests_per_minute": 1},
		Environment:   environment,
		APIScope:      scope,
	}
}

func reject(reason string) domain.VerificationResult {
	return domain.VerificationResult{
		Decision: domain.DecisionRejected,
		Reasons:  []string{reason},
	}
}
