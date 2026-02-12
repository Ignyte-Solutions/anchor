package v2

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const Version = 2

type Delegation struct {
	ParentCapabilityID string `json:"parent_capability_id"`
	Depth              int    `json:"depth"`
	MaxDepth           int    `json:"max_depth"`
}

type ConstraintSet struct {
	ResourceLimits         map[string]int64 `json:"resource_limits"`
	SpendLimits            map[string]int64 `json:"spend_limits"`
	APIScopes              []string         `json:"api_scopes"`
	RateLimits             map[string]int64 `json:"rate_limits"`
	EnvironmentConstraints []string         `json:"environment_constraints"`
}

type Capability struct {
	Version         int           `json:"version"`
	CapabilityID    string        `json:"capability_id"`
	IssuerID        string        `json:"issuer_id"`
	IssuerKID       string        `json:"issuer_kid"`
	AgentID         string        `json:"agent_id"`
	Audience        string        `json:"audience"`
	AllowedActions  []string      `json:"allowed_actions"`
	Constraints     ConstraintSet `json:"constraints"`
	Delegation      Delegation    `json:"delegation"`
	PolicyHash      string        `json:"policy_hash"`
	TransparencyRef string        `json:"transparency_ref"`
	IssuedAt        time.Time     `json:"issued_at"`
	ExpiresAt       time.Time     `json:"expires_at"`
	Nonce           string        `json:"nonce"`
	Signature       string        `json:"signature"`
}

type ConstraintEvidence struct {
	ResourceUsage map[string]int64 `json:"resource_usage"`
	SpendUsage    map[string]int64 `json:"spend_usage"`
	RateUsage     map[string]int64 `json:"rate_usage"`
	Environment   string           `json:"environment"`
	APIScope      string           `json:"api_scope"`
}

type ActionEnvelope struct {
	ActionID           string             `json:"action_id"`
	AgentID            string             `json:"agent_id"`
	CapabilityID       string             `json:"capability_id"`
	Audience           string             `json:"audience"`
	ActionType         string             `json:"action_type"`
	ActionPayload      json.RawMessage    `json:"action_payload"`
	ConstraintEvidence ConstraintEvidence `json:"constraint_evidence"`
	ChallengeNonce     string             `json:"challenge_nonce,omitempty"`
	Timestamp          time.Time          `json:"timestamp"`
	AgentSignature     string             `json:"agent_signature"`
}

type VerificationDecision string

const (
	DecisionAuthorized VerificationDecision = "AUTHORIZED"
	DecisionRejected   VerificationDecision = "REJECTED"
)

type ReasonCode string

const (
	ReasonCodeReferenceTimeMissing        ReasonCode = "ERR_REFERENCE_TIME_MISSING"
	ReasonCodeIssuerMismatch              ReasonCode = "ERR_ISSUER_MISMATCH"
	ReasonCodeCapabilityInvalid           ReasonCode = "ERR_CAPABILITY_INVALID"
	ReasonCodeCapabilitySignatureInvalid  ReasonCode = "ERR_CAPABILITY_SIGNATURE_INVALID"
	ReasonCodeCapabilityNotYetValid       ReasonCode = "ERR_CAPABILITY_NOT_YET_VALID"
	ReasonCodeCapabilityExpired           ReasonCode = "ERR_CAPABILITY_EXPIRED"
	ReasonCodeCapabilityRevoked           ReasonCode = "ERR_CAPABILITY_REVOKED"
	ReasonCodeAgentMismatch               ReasonCode = "ERR_AGENT_MISMATCH"
	ReasonCodeActionInvalid               ReasonCode = "ERR_ACTION_INVALID"
	ReasonCodeActionSignatureInvalid      ReasonCode = "ERR_ACTION_SIGNATURE_INVALID"
	ReasonCodeCapabilityBindingMismatch   ReasonCode = "ERR_CAPABILITY_BINDING_MISMATCH"
	ReasonCodeActionNotAllowed            ReasonCode = "ERR_ACTION_NOT_ALLOWED"
	ReasonCodeAudienceMismatch            ReasonCode = "ERR_AUDIENCE_MISMATCH"
	ReasonCodeDelegationDepthExceeded     ReasonCode = "ERR_DELEGATION_DEPTH_EXCEEDED"
	ReasonCodePolicyHashMismatch          ReasonCode = "ERR_POLICY_HASH_MISMATCH"
	ReasonCodePolicyHookRejected          ReasonCode = "ERR_POLICY_HOOK_REJECTED"
	ReasonCodeConstraintViolation         ReasonCode = "ERR_CONSTRAINT_VIOLATION"
	ReasonCodeChallengeRequired           ReasonCode = "ERR_CHALLENGE_REQUIRED"
	ReasonCodeReplayDetected              ReasonCode = "ERR_REPLAY_DETECTED"
	ReasonCodeTrustBundleExpired          ReasonCode = "ERR_TRUST_BUNDLE_EXPIRED"
	ReasonCodeTrustBundleSignatureInvalid ReasonCode = "ERR_TRUST_BUNDLE_SIGNATURE_INVALID"
	ReasonCodeIssuerKeyOutOfWindow        ReasonCode = "ERR_ISSUER_KEY_OUT_OF_WINDOW"
	ReasonCodeTransparencyInvalid         ReasonCode = "ERR_TRANSPARENCY_INVALID"
	ReasonCodeIssuerKeyMissing            ReasonCode = "ERR_ISSUER_KEY_MISSING"
)

type ReplayStatus string

const (
	ReplayStatusUnknown ReplayStatus = "UNKNOWN"
	ReplayStatusFresh   ReplayStatus = "FRESH"
	ReplayStatusReplay  ReplayStatus = "REPLAY"
)

type VerificationResult struct {
	Decision       VerificationDecision `json:"decision"`
	ReasonCodes    []ReasonCode         `json:"reason_codes"`
	Reasons        []string             `json:"reasons"`
	ReplayStatus   ReplayStatus         `json:"replay_status"`
	PolicyHashSeen string               `json:"policy_hash_seen"`
}

type TrustBundleIssuer struct {
	IssuerID      string    `json:"issuer_id"`
	IssuerKID     string    `json:"issuer_kid"`
	PublicKey     string    `json:"public_key"`
	ValidFrom     time.Time `json:"valid_from"`
	ValidUntil    time.Time `json:"valid_until"`
	AssuranceTier string    `json:"assurance_tier"`
}

type TrustBundle struct {
	BundleID           string              `json:"bundle_id"`
	IssuedAt           time.Time           `json:"issued_at"`
	ExpiresAt          time.Time           `json:"expires_at"`
	Issuers            []TrustBundleIssuer `json:"issuers"`
	RevocationPointers []string            `json:"revocation_pointers"`
	Signature          string              `json:"signature"`
	SignerPublicKeyKID string              `json:"signer_public_key_kid"`
}

func (c ConstraintSet) Validate() error {
	if c.ResourceLimits == nil {
		return errors.New("constraints.resource_limits is required")
	}
	if c.SpendLimits == nil {
		return errors.New("constraints.spend_limits is required")
	}
	if c.APIScopes == nil {
		return errors.New("constraints.api_scopes is required")
	}
	if c.RateLimits == nil {
		return errors.New("constraints.rate_limits is required")
	}
	if c.EnvironmentConstraints == nil {
		return errors.New("constraints.environment_constraints is required")
	}
	return nil
}

func (d Delegation) Validate() error {
	if d.Depth < 0 {
		return errors.New("delegation.depth must be >= 0")
	}
	if d.MaxDepth < 0 {
		return errors.New("delegation.max_depth must be >= 0")
	}
	if d.Depth > d.MaxDepth {
		return errors.New("delegation.depth must be <= delegation.max_depth")
	}
	if d.Depth > 0 && d.ParentCapabilityID == "" {
		return errors.New("delegation.parent_capability_id is required when depth > 0")
	}
	return nil
}

func (c Capability) ValidateUnsigned() error {
	if c.Version != Version {
		return fmt.Errorf("version must be %d", Version)
	}
	if c.IssuerID == "" {
		return errors.New("issuer_id is required")
	}
	if c.IssuerKID == "" {
		return errors.New("issuer_kid is required")
	}
	if c.AgentID == "" {
		return errors.New("agent_id is required")
	}
	if c.Audience == "" {
		return errors.New("audience is required")
	}
	if len(c.AllowedActions) == 0 {
		return errors.New("allowed_actions must not be empty")
	}
	if c.PolicyHash == "" {
		return errors.New("policy_hash is required")
	}
	if c.IssuedAt.IsZero() || c.ExpiresAt.IsZero() {
		return errors.New("issued_at and expires_at are required")
	}
	if !c.ExpiresAt.After(c.IssuedAt) {
		return errors.New("expires_at must be after issued_at")
	}
	if c.Nonce == "" {
		return errors.New("nonce is required")
	}
	if err := c.Constraints.Validate(); err != nil {
		return err
	}
	if err := c.Delegation.Validate(); err != nil {
		return err
	}
	return nil
}

func (e ConstraintEvidence) Validate() error {
	if e.ResourceUsage == nil {
		return errors.New("constraint_evidence.resource_usage is required")
	}
	if e.SpendUsage == nil {
		return errors.New("constraint_evidence.spend_usage is required")
	}
	if e.RateUsage == nil {
		return errors.New("constraint_evidence.rate_usage is required")
	}
	if e.Environment == "" {
		return errors.New("constraint_evidence.environment is required")
	}
	if e.APIScope == "" {
		return errors.New("constraint_evidence.api_scope is required")
	}
	return nil
}

func (a ActionEnvelope) ValidateUnsigned() error {
	if a.AgentID == "" {
		return errors.New("agent_id is required")
	}
	if a.CapabilityID == "" {
		return errors.New("capability_id is required")
	}
	if a.Audience == "" {
		return errors.New("audience is required")
	}
	if a.ActionType == "" {
		return errors.New("action_type is required")
	}
	if len(a.ActionPayload) == 0 {
		return errors.New("action_payload is required")
	}
	if a.Timestamp.IsZero() {
		return errors.New("timestamp is required")
	}
	if err := a.ConstraintEvidence.Validate(); err != nil {
		return err
	}
	return nil
}

func (b TrustBundle) Validate() error {
	if b.BundleID == "" {
		return errors.New("bundle_id is required")
	}
	if b.IssuedAt.IsZero() || b.ExpiresAt.IsZero() {
		return errors.New("issued_at and expires_at are required")
	}
	if !b.ExpiresAt.After(b.IssuedAt) {
		return errors.New("expires_at must be after issued_at")
	}
	if len(b.Issuers) == 0 {
		return errors.New("issuers must not be empty")
	}
	if b.Signature == "" {
		return errors.New("signature is required")
	}
	if b.SignerPublicKeyKID == "" {
		return errors.New("signer_public_key_kid is required")
	}
	return nil
}
