package api

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/ignyte-solutions/ignyte-anchor/internal/audit"
	anchorcrypto "github.com/ignyte-solutions/ignyte-anchor/internal/crypto"
	"github.com/ignyte-solutions/ignyte-anchor/internal/domain"
	"github.com/ignyte-solutions/ignyte-anchor/internal/issuer"
	"github.com/ignyte-solutions/ignyte-anchor/internal/verifier"
)

type Server struct {
	config        Config
	mux           *http.ServeMux
	issuerService *issuer.Service
	auditLog      *audit.Log
	verifier      *verifier.Engine
	clock         issuer.Clock
}

type issueCapabilityRequest struct {
	AgentPublicKey string                       `json:"agent_public_key"`
	AllowedActions []string                     `json:"allowed_actions"`
	Constraints    domain.CapabilityConstraints `json:"constraints"`
	ExpiresAt      time.Time                    `json:"expires_at"`
	Nonce          string                       `json:"nonce"`
}

type verifyActionRequest struct {
	Capability           domain.Capability     `json:"capability"`
	Action               domain.ActionEnvelope `json:"action"`
	IssuerPublicKey      string                `json:"issuer_public_key"`
	AgentPublicKey       string                `json:"agent_public_key"`
	RevokedCapabilityIDs []string              `json:"revoked_capability_ids"`
}

func NewServer(config Config) (*Server, error) {
	issuerService, err := issuer.NewService(config.IssuerPrivateKey, rand.Reader, issuer.RealClock{})
	if err != nil {
		return nil, fmt.Errorf("create issuer service: %w", err)
	}
	auditLog, err := audit.Open(config.AuditLogPath)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	server := &Server{
		config:        config,
		mux:           http.NewServeMux(),
		issuerService: issuerService,
		auditLog:      auditLog,
		verifier:      verifier.New(),
		clock:         issuer.RealClock{},
	}
	server.registerRoutes()
	return server, nil
}

func (s *Server) Handler() http.Handler {
	return s.withCORS(s.mux)
}

func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	return s.auditLog.Close()
}

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("/healthz", s.handleHealth)
	s.mux.HandleFunc("/v1/capabilities", s.handleIssueCapability)
	s.mux.HandleFunc("/v1/actions/verify", s.handleVerifyAction)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
		"name":   "Ignyte Anchor",
		"api":    s.config.PublicAPIBaseURL,
	})
}

func (s *Server) handleIssueCapability(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var request issueCapabilityRequest
	if err := decodeJSON(r, &request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	capabilityToken, err := s.issuerService.IssueCapability(issuer.IssueCapabilityRequest{
		AgentPublicKey: request.AgentPublicKey,
		AllowedActions: request.AllowedActions,
		Constraints:    request.Constraints,
		ExpiresAt:      request.ExpiresAt,
		Nonce:          request.Nonce,
	})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	now := s.clock.Now().UTC()
	if _, err := s.auditLog.Append(audit.EventCapabilityIssued, capabilityToken, now); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("audit append failed: %v", err)})
		return
	}
	issuerInfo, err := s.issuerService.Issuer()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"capability": capabilityToken,
		"issuer":     issuerInfo,
	})
}

func (s *Server) handleVerifyAction(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var request verifyActionRequest
	if err := decodeJSON(r, &request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	issuerPublicKey, err := anchorcrypto.PublicKeyFromBase64(request.IssuerPublicKey)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid issuer_public_key: %v", err)})
		return
	}
	agentPublicKey, err := anchorcrypto.PublicKeyFromBase64(request.AgentPublicKey)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("invalid agent_public_key: %v", err)})
		return
	}

	revoked := make(map[string]struct{}, len(request.RevokedCapabilityIDs))
	for _, capabilityID := range request.RevokedCapabilityIDs {
		if capabilityID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "revoked_capability_ids must not include empty values"})
			return
		}
		revoked[capabilityID] = struct{}{}
	}

	result := s.verifier.Verify(verifier.VerifyRequest{
		Capability:      request.Capability,
		Action:          request.Action,
		IssuerPublicKey: issuerPublicKey,
		AgentPublicKey:  agentPublicKey,
		ReferenceTime:   request.Action.Timestamp,
		RevocationList:  verifier.StaticRevocationList{Revoked: revoked},
	})

	now := s.clock.Now().UTC()
	if _, err = s.auditLog.Append(audit.EventActionExecuted, request.Action, now); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("audit append failed: %v", err)})
		return
	}
	if _, err = s.auditLog.Append(audit.EventVerificationResult, result, now); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("audit append failed: %v", err)})
		return
	}

	writeJSON(w, http.StatusOK, result)
}

func (s *Server) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && slices.Contains(s.config.AllowedOrigins, origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		}
		next.ServeHTTP(w, r)
	})
}

func decodeJSON(r *http.Request, out any) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return fmt.Errorf("invalid request body: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != nil {
		if !errors.Is(err, io.EOF) {
			return fmt.Errorf("request body must contain a single JSON object")
		}
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(body)
}
