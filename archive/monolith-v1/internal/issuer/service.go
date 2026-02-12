package issuer

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/ignyte-solutions/ignyte-anchor/internal/capability"
	anchorcrypto "github.com/ignyte-solutions/ignyte-anchor/internal/crypto"
	"github.com/ignyte-solutions/ignyte-anchor/internal/domain"
)

type Clock interface {
	Now() time.Time
}

type RealClock struct{}

func (RealClock) Now() time.Time {
	return time.Now().UTC()
}

type Service struct {
	issuerPrivateKey ed25519.PrivateKey
	issuerPublicKey  ed25519.PublicKey
	issuerID         string
	nonceReader      io.Reader
	clock            Clock
}

type IssueCapabilityRequest struct {
	AgentPublicKey string                       `json:"agent_public_key"`
	AllowedActions []string                     `json:"allowed_actions"`
	Constraints    domain.CapabilityConstraints `json:"constraints"`
	ExpiresAt      time.Time                    `json:"expires_at"`
	Nonce          string                       `json:"nonce"`
}

func NewService(issuerPrivateKey ed25519.PrivateKey, nonceReader io.Reader, clock Clock) (*Service, error) {
	if len(issuerPrivateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("issuer private key must be %d bytes", ed25519.PrivateKeySize)
	}
	if nonceReader == nil {
		return nil, fmt.Errorf("nonce reader is required")
	}
	if clock == nil {
		return nil, fmt.Errorf("clock is required")
	}
	issuerPublic := issuerPrivateKey.Public().(ed25519.PublicKey)
	issuerID, err := anchorcrypto.DeriveIDFromPublicKey(issuerPublic)
	if err != nil {
		return nil, err
	}
	return &Service{
		issuerPrivateKey: issuerPrivateKey,
		issuerPublicKey:  issuerPublic,
		issuerID:         issuerID,
		nonceReader:      nonceReader,
		clock:            clock,
	}, nil
}

func (s *Service) Issuer() (domain.Issuer, error) {
	if s == nil {
		return domain.Issuer{}, fmt.Errorf("issuer service is required")
	}
	return domain.Issuer{
		IssuerID:  s.issuerID,
		PublicKey: anchorcrypto.PublicKeyToBase64(s.issuerPublicKey),
	}, nil
}

func (s *Service) IssueCapability(request IssueCapabilityRequest) (domain.Capability, error) {
	if s == nil {
		return domain.Capability{}, fmt.Errorf("issuer service is required")
	}
	if len(request.AllowedActions) == 0 {
		return domain.Capability{}, fmt.Errorf("allowed_actions must not be empty")
	}
	if err := request.Constraints.Validate(); err != nil {
		return domain.Capability{}, err
	}
	agentPublicKey, err := anchorcrypto.PublicKeyFromBase64(request.AgentPublicKey)
	if err != nil {
		return domain.Capability{}, fmt.Errorf("invalid agent public key: %w", err)
	}
	agentID, err := anchorcrypto.DeriveIDFromPublicKey(agentPublicKey)
	if err != nil {
		return domain.Capability{}, err
	}
	issuedAt := s.clock.Now().UTC()
	if !request.ExpiresAt.After(issuedAt) {
		return domain.Capability{}, fmt.Errorf("expires_at must be after issued_at")
	}

	nonce := request.Nonce
	if nonce == "" {
		randomNonce, nonceErr := generateNonce(s.nonceReader)
		if nonceErr != nil {
			return domain.Capability{}, nonceErr
		}
		nonce = randomNonce
	}

	allowedActions := append([]string(nil), request.AllowedActions...)
	sort.Strings(allowedActions)
	constraints := normalizeConstraints(request.Constraints)

	capabilityToken := domain.Capability{
		Version:        domain.CapabilityVersion,
		IssuerID:       s.issuerID,
		AgentID:        agentID,
		AllowedActions: allowedActions,
		Constraints:    constraints,
		IssuedAt:       issuedAt,
		ExpiresAt:      request.ExpiresAt.UTC(),
		Nonce:          nonce,
	}
	if err := capability.Sign(&capabilityToken, s.issuerPrivateKey); err != nil {
		return domain.Capability{}, err
	}
	return capabilityToken, nil
}

func generateNonce(reader io.Reader) (string, error) {
	nonce := make([]byte, 32)
	if _, err := io.ReadFull(reader, nonce); err != nil {
		return "", fmt.Errorf("read nonce: %w", err)
	}
	return base64.StdEncoding.EncodeToString(nonce), nil
}

func normalizeConstraints(input domain.CapabilityConstraints) domain.CapabilityConstraints {
	resourceLimits := make(map[string]int64, len(input.ResourceLimits))
	for key, value := range input.ResourceLimits {
		resourceLimits[key] = value
	}
	spendLimits := make(map[string]int64, len(input.SpendLimits))
	for key, value := range input.SpendLimits {
		spendLimits[key] = value
	}
	rateLimits := make(map[string]int64, len(input.RateLimits))
	for key, value := range input.RateLimits {
		rateLimits[key] = value
	}
	apiScopes := append([]string(nil), input.APIScopes...)
	environments := append([]string(nil), input.EnvironmentConstraints...)
	sort.Strings(apiScopes)
	sort.Strings(environments)
	return domain.CapabilityConstraints{
		ResourceLimits:         resourceLimits,
		SpendLimits:            spendLimits,
		APIScopes:              apiScopes,
		RateLimits:             rateLimits,
		EnvironmentConstraints: environments,
	}
}
