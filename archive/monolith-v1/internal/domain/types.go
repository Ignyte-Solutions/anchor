package domain

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const (
	CapabilityVersion = 1
)

type Issuer struct {
	IssuerID  string            `json:"issuer_id"`
	PublicKey string            `json:"public_key"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

type Agent struct {
	AgentID   string `json:"agent_id"`
	PublicKey string `json:"public_key"`
	IssuerID  string `json:"issuer_id"`
}

type CapabilityConstraints struct {
	ResourceLimits         map[string]int64 `json:"resource_limits"`
	SpendLimits            map[string]int64 `json:"spend_limits"`
	APIScopes              []string         `json:"api_scopes"`
	RateLimits             map[string]int64 `json:"rate_limits"`
	EnvironmentConstraints []string         `json:"environment_constraints"`
}

type Capability struct {
	Version        int                   `json:"version"`
	CapabilityID   string                `json:"capability_id"`
	IssuerID       string                `json:"issuer_id"`
	AgentID        string                `json:"agent_id"`
	AllowedActions []string              `json:"allowed_actions"`
	Constraints    CapabilityConstraints `json:"constraints"`
	IssuedAt       time.Time             `json:"issued_at"`
	ExpiresAt      time.Time             `json:"expires_at"`
	Nonce          string                `json:"nonce"`
	Signature      string                `json:"signature"`
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
	ActionType         string             `json:"action_type"`
	ActionPayload      json.RawMessage    `json:"action_payload"`
	ConstraintEvidence ConstraintEvidence `json:"constraint_evidence"`
	Timestamp          time.Time          `json:"timestamp"`
	AgentSignature     string             `json:"agent_signature"`
}

type VerificationDecision string

const (
	DecisionAuthorized VerificationDecision = "AUTHORIZED"
	DecisionRejected   VerificationDecision = "REJECTED"
)

type VerificationResult struct {
	Decision VerificationDecision `json:"decision"`
	Reasons  []string             `json:"reasons"`
}

func (c CapabilityConstraints) Validate() error {
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

	for k, v := range c.ResourceLimits {
		if k == "" {
			return errors.New("constraints.resource_limits keys must not be empty")
		}
		if v < 0 {
			return fmt.Errorf("constraints.resource_limits[%s] must be non-negative", k)
		}
	}
	for k, v := range c.SpendLimits {
		if k == "" {
			return errors.New("constraints.spend_limits keys must not be empty")
		}
		if v < 0 {
			return fmt.Errorf("constraints.spend_limits[%s] must be non-negative", k)
		}
	}
	for _, scope := range c.APIScopes {
		if scope == "" {
			return errors.New("constraints.api_scopes values must not be empty")
		}
	}
	for k, v := range c.RateLimits {
		if k == "" {
			return errors.New("constraints.rate_limits keys must not be empty")
		}
		if v < 0 {
			return fmt.Errorf("constraints.rate_limits[%s] must be non-negative", k)
		}
	}
	for _, env := range c.EnvironmentConstraints {
		if env == "" {
			return errors.New("constraints.environment_constraints values must not be empty")
		}
	}
	return nil
}

func (c Capability) ValidateUnsigned() error {
	if c.Version != CapabilityVersion {
		return fmt.Errorf("version must be %d", CapabilityVersion)
	}
	if c.IssuerID == "" {
		return errors.New("issuer_id is required")
	}
	if c.AgentID == "" {
		return errors.New("agent_id is required")
	}
	if c.AllowedActions == nil {
		return errors.New("allowed_actions is required")
	}
	if len(c.AllowedActions) == 0 {
		return errors.New("allowed_actions must not be empty")
	}
	for _, action := range c.AllowedActions {
		if action == "" {
			return errors.New("allowed_actions values must not be empty")
		}
	}
	if c.IssuedAt.IsZero() {
		return errors.New("issued_at is required")
	}
	if c.ExpiresAt.IsZero() {
		return errors.New("expires_at is required")
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
	for k, v := range e.ResourceUsage {
		if k == "" {
			return errors.New("constraint_evidence.resource_usage keys must not be empty")
		}
		if v < 0 {
			return fmt.Errorf("constraint_evidence.resource_usage[%s] must be non-negative", k)
		}
	}
	for k, v := range e.SpendUsage {
		if k == "" {
			return errors.New("constraint_evidence.spend_usage keys must not be empty")
		}
		if v < 0 {
			return fmt.Errorf("constraint_evidence.spend_usage[%s] must be non-negative", k)
		}
	}
	for k, v := range e.RateUsage {
		if k == "" {
			return errors.New("constraint_evidence.rate_usage keys must not be empty")
		}
		if v < 0 {
			return fmt.Errorf("constraint_evidence.rate_usage[%s] must be non-negative", k)
		}
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
