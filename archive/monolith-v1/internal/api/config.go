package api

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"strings"

	anchorcrypto "github.com/ignyte-solutions/ignyte-anchor/internal/crypto"
)

type Config struct {
	ServerAddr       string
	PublicAPIBaseURL string
	AuditLogPath     string
	AllowedOrigins   []string
	IssuerPrivateKey ed25519.PrivateKey
}

func LoadConfigFromEnv() (Config, error) {
	serverAddr, ok := os.LookupEnv("IGNYTE_ANCHOR_SERVER_ADDR")
	if !ok || strings.TrimSpace(serverAddr) == "" {
		return Config{}, fmt.Errorf("IGNYTE_ANCHOR_SERVER_ADDR is required")
	}
	publicAPIBaseURL, ok := os.LookupEnv("IGNYTE_ANCHOR_API_BASE_URL")
	if !ok || strings.TrimSpace(publicAPIBaseURL) == "" {
		return Config{}, fmt.Errorf("IGNYTE_ANCHOR_API_BASE_URL is required")
	}
	auditLogPath, ok := os.LookupEnv("IGNYTE_ANCHOR_AUDIT_LOG_PATH")
	if !ok || strings.TrimSpace(auditLogPath) == "" {
		return Config{}, fmt.Errorf("IGNYTE_ANCHOR_AUDIT_LOG_PATH is required")
	}
	allowedOriginsRaw, ok := os.LookupEnv("IGNYTE_ANCHOR_ALLOWED_ORIGINS")
	if !ok || strings.TrimSpace(allowedOriginsRaw) == "" {
		return Config{}, fmt.Errorf("IGNYTE_ANCHOR_ALLOWED_ORIGINS is required")
	}
	issuerPrivateKeyB64, ok := os.LookupEnv("IGNYTE_ANCHOR_ISSUER_PRIVATE_KEY_B64")
	if !ok || strings.TrimSpace(issuerPrivateKeyB64) == "" {
		return Config{}, fmt.Errorf("IGNYTE_ANCHOR_ISSUER_PRIVATE_KEY_B64 is required")
	}
	issuerPrivateKey, err := anchorcrypto.PrivateKeyFromBase64(strings.TrimSpace(issuerPrivateKeyB64))
	if err != nil {
		return Config{}, fmt.Errorf("parse IGNYTE_ANCHOR_ISSUER_PRIVATE_KEY_B64: %w", err)
	}
	origins := parseCommaSeparated(allowedOriginsRaw)
	if len(origins) == 0 {
		return Config{}, fmt.Errorf("IGNYTE_ANCHOR_ALLOWED_ORIGINS must include at least one origin")
	}

	return Config{
		ServerAddr:       strings.TrimSpace(serverAddr),
		PublicAPIBaseURL: strings.TrimSpace(publicAPIBaseURL),
		AuditLogPath:     strings.TrimSpace(auditLogPath),
		AllowedOrigins:   origins,
		IssuerPrivateKey: issuerPrivateKey,
	}, nil
}

func parseCommaSeparated(input string) []string {
	parts := strings.Split(input, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}
