package authn

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"stealthlink/internal/config"
)

func TestAuthorizeStaticProvider(t *testing.T) {
	cfg := &config.Config{}
	cfg.Auth.Providers = []config.AuthProviderConfig{{
		Name:    "static-main",
		Type:    "static",
		Enabled: true,
		Static:  config.StaticAuthProviderConfig{AgentTokens: map[string]string{"agent-1": "tok"}},
	}}
	cfg.Auth.Strict = true

	if !AuthorizeAgent(cfg, "agent-1", "tok") {
		t.Fatalf("static provider should authorize")
	}
	if AuthorizeAgent(cfg, "agent-1", "bad") {
		t.Fatalf("static provider should reject bad token")
	}
}

func TestAuthorizeOIDCProvider(t *testing.T) {
	secret := "supersecret"
	cfg := &config.Config{}
	cfg.Auth.Providers = []config.AuthProviderConfig{{
		Name:    "oidc-main",
		Type:    "oidc",
		Enabled: true,
		OIDC: config.OIDCAuthProviderConfig{
			Issuer:         "https://issuer.example",
			Audience:       "stealthlink",
			HS256Secret:    secret,
			RequiredGroups: []string{"ops"},
			ClockSkew:      "30s",
		},
	}}
	cfg.Auth.Strict = true

	tok := makeJWT(t, secret, map[string]any{
		"iss":    "https://issuer.example",
		"sub":    "agent-1",
		"aud":    "stealthlink",
		"exp":    time.Now().Add(1 * time.Minute).Unix(),
		"groups": []string{"ops", "sre"},
	})
	if !AuthorizeAgent(cfg, "agent-1", tok) {
		t.Fatalf("oidc provider should authorize")
	}
}

func makeJWT(t *testing.T, secret string, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": "HS256", "typ": "JWT"}
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(claims)
	a := base64.RawURLEncoding.EncodeToString(h)
	b := base64.RawURLEncoding.EncodeToString(p)
	signed := a + "." + b
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(signed))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf("%s.%s", signed, sig)
}
