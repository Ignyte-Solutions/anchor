package anchorgo

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ignyte-solutions/ignyte-anchor/internal/domain"
)

type Client struct {
	baseURL    string
	httpClient *http.Client
}

type IssueCapabilityRequest struct {
	AgentPublicKey string                       `json:"agent_public_key"`
	AllowedActions []string                     `json:"allowed_actions"`
	Constraints    domain.CapabilityConstraints `json:"constraints"`
	ExpiresAt      time.Time                    `json:"expires_at"`
	Nonce          string                       `json:"nonce"`
}

type IssueCapabilityResponse struct {
	Capability domain.Capability `json:"capability"`
	Issuer     domain.Issuer     `json:"issuer"`
}

type VerifyActionRequest struct {
	Capability           domain.Capability     `json:"capability"`
	Action               domain.ActionEnvelope `json:"action"`
	IssuerPublicKey      string                `json:"issuer_public_key"`
	AgentPublicKey       string                `json:"agent_public_key"`
	RevokedCapabilityIDs []string              `json:"revoked_capability_ids"`
}

func NewClient(baseURL string, httpClient *http.Client) (*Client, error) {
	if strings.TrimSpace(baseURL) == "" {
		return nil, fmt.Errorf("baseURL is required")
	}
	if httpClient == nil {
		return nil, fmt.Errorf("httpClient is required")
	}
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), httpClient: httpClient}, nil
}

func (c *Client) IssueCapability(ctx context.Context, request IssueCapabilityRequest) (IssueCapabilityResponse, error) {
	if c == nil {
		return IssueCapabilityResponse{}, fmt.Errorf("client is required")
	}
	response, err := c.doJSON(ctx, http.MethodPost, "/v1/capabilities", request)
	if err != nil {
		return IssueCapabilityResponse{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		return IssueCapabilityResponse{}, parseAPIError(response)
	}
	var out IssueCapabilityResponse
	if err := json.NewDecoder(response.Body).Decode(&out); err != nil {
		return IssueCapabilityResponse{}, fmt.Errorf("decode issue capability response: %w", err)
	}
	return out, nil
}

func (c *Client) VerifyAction(ctx context.Context, request VerifyActionRequest) (domain.VerificationResult, error) {
	if c == nil {
		return domain.VerificationResult{}, fmt.Errorf("client is required")
	}
	response, err := c.doJSON(ctx, http.MethodPost, "/v1/actions/verify", request)
	if err != nil {
		return domain.VerificationResult{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return domain.VerificationResult{}, parseAPIError(response)
	}
	var out domain.VerificationResult
	if err := json.NewDecoder(response.Body).Decode(&out); err != nil {
		return domain.VerificationResult{}, fmt.Errorf("decode verify action response: %w", err)
	}
	return out, nil
}

func (c *Client) doJSON(ctx context.Context, method, path string, request any) (*http.Response, error) {
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	httpRequest, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	response, err := c.httpClient.Do(httpRequest)
	if err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}
	return response, nil
}

func parseAPIError(response *http.Response) error {
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("api status %d (failed to read body: %w)", response.StatusCode, err)
	}
	if len(responseBody) == 0 {
		return fmt.Errorf("api status %d", response.StatusCode)
	}
	return fmt.Errorf("api status %d: %s", response.StatusCode, string(responseBody))
}
