package authn

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"stealthlink/internal/config"
)

// AuthorizeAgent applies configured auth providers. If no providers are configured,
// it falls back to legacy security.agent_tokens / shared key behavior.
func AuthorizeAgent(cfg *config.Config, agentID, token string) bool {
	providers := enabledProviders(cfg.Auth.Providers)
	if len(providers) == 0 {
		return legacyAuthorize(cfg, agentID, token)
	}

	for _, p := range providers {
		switch p.Type {
		case "static":
			if staticAuthorize(cfg, p, agentID, token) {
				return true
			}
		case "oidc":
			if oidcAuthorize(p, agentID, token) {
				return true
			}
		case "radius":
			if radiusAuthorize(p, agentID, token) {
				return true
			}
		}
	}

	if cfg.Auth.Strict {
		return false
	}
	// In non-strict mode, fall back to legacy static auth.
	return legacyAuthorize(cfg, agentID, token)
}

func enabledProviders(in []config.AuthProviderConfig) []config.AuthProviderConfig {
	out := make([]config.AuthProviderConfig, 0, len(in))
	for _, p := range in {
		if p.Enabled {
			out = append(out, p)
		}
	}
	return out
}

func legacyAuthorize(cfg *config.Config, agentID, token string) bool {
	if len(cfg.Security.AgentTokens) == 0 {
		return token == cfg.AgentToken(agentID)
	}
	expected, ok := cfg.Security.AgentTokens[agentID]
	if !ok {
		return false
	}
	return token == expected
}

func staticAuthorize(cfg *config.Config, p config.AuthProviderConfig, agentID, token string) bool {
	if len(p.Static.AgentTokens) == 0 {
		return legacyAuthorize(cfg, agentID, token)
	}
	expected, ok := p.Static.AgentTokens[agentID]
	if !ok {
		return false
	}
	return token == expected
}

type oidcClaims struct {
	Iss    string         `json:"iss"`
	Sub    string         `json:"sub"`
	Aud    any            `json:"aud"`
	Exp    int64          `json:"exp"`
	Nbf    int64          `json:"nbf"`
	Groups []string       `json:"groups"`
	Scope  string         `json:"scope"`
	Extra  map[string]any `json:"-"`
}

func oidcAuthorize(p config.AuthProviderConfig, agentID, token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}

	signed := parts[0] + "." + parts[1]
	expectedSig := signHS256(signed, p.OIDC.HS256Secret)
	if !hmac.Equal([]byte(expectedSig), []byte(parts[2])) {
		return false
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return false
	}

	iss, _ := claims["iss"].(string)
	sub, _ := claims["sub"].(string)
	if iss != p.OIDC.Issuer || sub != agentID {
		return false
	}
	if !audienceMatches(claims["aud"], p.OIDC.Audience) {
		return false
	}

	clockSkew, err := time.ParseDuration(p.OIDC.ClockSkew)
	if err != nil {
		clockSkew = 30 * time.Second
	}
	now := time.Now().Unix()
	if exp, ok := numberToInt64(claims["exp"]); ok {
		if now > exp+int64(clockSkew.Seconds()) {
			return false
		}
	}
	if nbf, ok := numberToInt64(claims["nbf"]); ok {
		if now+int64(clockSkew.Seconds()) < nbf {
			return false
		}
	}

	if len(p.OIDC.RequiredGroups) == 0 {
		return true
	}
	groups := extractGroups(claims)
	if len(groups) == 0 {
		return false
	}
	return containsAll(groups, p.OIDC.RequiredGroups)
}

func radiusAuthorize(p config.AuthProviderConfig, agentID, token string) bool {
	if len(p.Radius.Users) > 0 {
		expected, ok := p.Radius.Users[agentID]
		return ok && token == expected
	}
	// Token format: radius:<agent_id>:<unix_ts>:<base64url_hmac>
	parts := strings.Split(token, ":")
	if len(parts) != 4 || parts[0] != "radius" || parts[1] != agentID {
		return false
	}
	ts, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return false
	}
	timeout, err := time.ParseDuration(p.Radius.Timeout)
	if err != nil {
		timeout = 2 * time.Second
	}
	now := time.Now().Unix()
	if now-ts > int64(timeout.Seconds()) || ts-now > int64(timeout.Seconds()) {
		return false
	}
	msg := fmt.Sprintf("%s:%s:%s", parts[0], parts[1], parts[2])
	expected := signHS256(msg, p.Radius.SharedSecret)
	return hmac.Equal([]byte(expected), []byte(parts[3]))
}

func signHS256(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	_, _ = h.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func audienceMatches(aud any, expected string) bool {
	switch v := aud.(type) {
	case string:
		return v == expected
	case []any:
		for _, x := range v {
			if s, ok := x.(string); ok && s == expected {
				return true
			}
		}
	}
	return false
}

func extractGroups(claims map[string]any) []string {
	if g, ok := claims["groups"].([]any); ok {
		out := make([]string, 0, len(g))
		for _, x := range g {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	if g, ok := claims["groups"].([]string); ok {
		return g
	}
	if scope, ok := claims["scope"].(string); ok {
		return strings.Fields(scope)
	}
	return nil
}

func containsAll(have []string, need []string) bool {
	set := make(map[string]struct{}, len(have))
	for _, s := range have {
		set[s] = struct{}{}
	}
	for _, s := range need {
		if _, ok := set[s]; !ok {
			return false
		}
	}
	return true
}

func numberToInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int64:
		return n, true
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return 0, false
		}
		return i, true
	default:
		return 0, false
	}
}
