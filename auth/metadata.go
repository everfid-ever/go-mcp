package auth

import (
	"encoding/json"
	"net/http"
)

// AuthorizationServerMetadata represents OAuth 2.0 Authorization Server Metadata (RFC 8414)
type AuthorizationServerMetadata struct {
	// REQUIRED: The authorization server's issuer identifier
	Issuer string `json:"issuer"`

	// REQUIRED: URL of the authorization endpoint
	AuthorizationEndpoint string `json:"authorization_endpoint"`

	// REQUIRED: URL of the token endpoint
	TokenEndpoint string `json:"token_endpoint"`

	// OPTIONAL: URL of the JWK Set document
	JWKSURI string `json:"jwks_uri,omitempty"`

	// OPTIONAL: URL of the Dynamic Client Registration endpoint
	RegistrationEndpoint string `json:"registration_endpoint,omitempty"`

	// OPTIONAL: JSON array of scope values supported
	ScopesSupported []string `json:"scopes_supported,omitempty"`

	// REQUIRED: JSON array of response_type values supported
	ResponseTypesSupported []string `json:"response_types_supported"`

	// OPTIONAL: JSON array of response_mode values supported
	ResponseModesSupported []string `json:"response_modes_supported,omitempty"`

	// OPTIONAL: JSON array of grant types supported
	GrantTypesSupported []string `json:"grant_types_supported,omitempty"`

	// OPTIONAL: JSON array of client authentication methods supported
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`

	// OPTIONAL: JSON array of signing algorithms supported
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`

	// OPTIONAL: URL of the revocation endpoint
	RevocationEndpoint string `json:"revocation_endpoint,omitempty"`

	// OPTIONAL: Client authentication methods supported by revocation endpoint
	RevocationEndpointAuthMethodsSupported []string `json:"revocation_endpoint_auth_methods_supported,omitempty"`

	// OPTIONAL: URL of the introspection endpoint
	IntrospectionEndpoint string `json:"introspection_endpoint,omitempty"`

	// OPTIONAL: Client authentication methods supported by introspection endpoint
	IntrospectionEndpointAuthMethodsSupported []string `json:"introspection_endpoint_auth_methods_supported,omitempty"`

	// OPTIONAL: JSON array of PKCE code challenge methods supported
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported,omitempty"`

	// RFC 8707: Resource Indicators
	// OPTIONAL: Boolean indicating support for resource indicators
	ResourceIndicatorsSupported bool `json:"resource_indicators_supported,omitempty"`

	// MCP-specific extensions
	MCPVersion             string   `json:"mcp_version,omitempty"`
	MCPTransportsSupported []string `json:"mcp_transports_supported,omitempty"`
}

// MetadataProvider generates authorization server metadata
type MetadataProvider struct {
	config   *ServerConfig
	baseURL  string
	metadata *AuthorizationServerMetadata
}

// NewMetadataProvider creates a new metadata provider
func NewMetadataProvider(config *ServerConfig, baseURL string) *MetadataProvider {
	mp := &MetadataProvider{
		config:  config,
		baseURL: baseURL,
	}
	mp.generateMetadata()
	return mp
}

// generateMetadata builds the metadata document
func (mp *MetadataProvider) generateMetadata() {
	grantTypes := make([]string, len(mp.config.SupportedGrantTypes))
	for i, gt := range mp.config.SupportedGrantTypes {
		grantTypes[i] = string(gt)
	}

	mp.metadata = &AuthorizationServerMetadata{
		Issuer:                mp.config.Issuer,
		AuthorizationEndpoint: mp.baseURL + "/oauth/authorize",
		TokenEndpoint:         mp.baseURL + "/oauth/token",
		RevocationEndpoint:    mp.baseURL + "/oauth/revoke",
		IntrospectionEndpoint: mp.baseURL + "/oauth/introspect",
		JWKSURI:               mp.baseURL + "/.well-known/jwks.json",

		ResponseTypesSupported: []string{"code"},
		ResponseModesSupported: []string{"query"},
		GrantTypesSupported:    grantTypes,

		TokenEndpointAuthMethodsSupported: []string{
			"client_secret_basic",
			"client_secret_post",
			"none", // For public clients
		},

		RevocationEndpointAuthMethodsSupported: []string{
			"client_secret_basic",
			"client_secret_post",
		},

		IntrospectionEndpointAuthMethodsSupported: []string{
			"client_secret_basic",
			"client_secret_post",
		},

		CodeChallengeMethodsSupported: []string{"S256"},

		// RFC 8707 support
		ResourceIndicatorsSupported: true,

		// MCP-specific
		MCPVersion:             "2025-03-26",
		MCPTransportsSupported: []string{"sse", "stdio"},

		ScopesSupported: []string{
			"read",
			"write",
			"tools:list",
			"tools:execute",
			"prompts:list",
			"prompts:execute",
			"resources:list",
			"resources:read",
		},
	}
}

// GetMetadata returns the metadata document
func (mp *MetadataProvider) GetMetadata() *AuthorizationServerMetadata {
	return mp.metadata
}

// ServeHTTP handles the metadata endpoint
func (mp *MetadataProvider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600") // Cache for 1 hour

	json.NewEncoder(w).Encode(mp.metadata)
}
