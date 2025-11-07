package auth

import "strings"

// ThirdPartyOAuthConfig holds configuration for a third-party OAuth provider
type ThirdPartyOAuthConfig struct {
	// Provider information
	ProviderName string

	// OAuth 2.1 endpoints
	AuthorizationURL string // Third-party /authorize endpoint
	TokenURL         string // Third-party /token endpoint
	UserInfoURL      string // Optional: to get user info

	// Client credentials (registered with third-party)
	ClientID     string
	ClientSecret string

	// Redirect URI (your MCP server's callback)
	RedirectURI string

	// Scopes to request from third-party
	Scopes []string

	// Optional: PKCE support
	UsePKCE bool
}

// ThirdPartyTokenResponse represents token response from third-party
type ThirdPartyTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	IDToken      string `json:"id_token,omitempty"` // For OIDC
}

// ThirdPartyUserInfo represents user info from third-party
type ThirdPartyUserInfo struct {
	Subject  string                 `json:"sub"`
	Email    string                 `json:"email,omitempty"`
	Name     string                 `json:"name,omitempty"`
	Username string                 `json:"preferred_username,omitempty"`
	Claims   map[string]interface{} `json:"-"` // Additional claims
}

// ParseScopes parses a space-separated scope string into a slice
func ParseScopes(scopeString string) []string {
	if scopeString == "" {
		return []string{}
	}

	scopes := strings.Split(scopeString, " ")

	// Remove empty strings
	result := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		trimmed := strings.TrimSpace(scope)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}

	return result
}
