package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OAuthClient handles OAuth flow with third-party providers
type OAuthClient struct {
	config      *ThirdPartyOAuthConfig
	mcpTokenGen *TokenGenerator
	store       Store
	stateStore  map[string]*OAuthState // In-memory state storage (use Redis in production)
	httpClient  *http.Client
}

// OAuthState stores temporary OAuth flow state
type OAuthState struct {
	State           string
	CodeVerifier    string // For PKCE
	CodeChallenge   string
	RedirectURI     string
	OriginalRequest string // Store original MCP client callback
	CreatedAt       time.Time
	ExpiresAt       time.Time
}

// NewOAuthClient creates a new OAuth client for third-party auth
func NewOAuthClient(
	config *ThirdPartyOAuthConfig,
	mcpTokenGen *TokenGenerator,
	store Store,
) *OAuthClient {
	return &OAuthClient{
		config:      config,
		mcpTokenGen: mcpTokenGen,
		store:       store,
		stateStore:  make(map[string]*OAuthState),
		httpClient:  &http.Client{Timeout: 30 * time.Second},
	}
}

// InitiateOAuthFlow handles the initial OAuth request from MCP Client
// This corresponds to "Initial OAuth Request" in your diagram
func (c *OAuthClient) InitiateOAuthFlow(w http.ResponseWriter, r *http.Request) {
	// Extract MCP client's callback URL (where to redirect after OAuth completes)
	mcpClientCallback := r.URL.Query().Get("redirect_uri")
	if mcpClientCallback == "" {
		http.Error(w, "Missing redirect_uri parameter", http.StatusBadRequest)
		return
	}

	// Generate state for CSRF protection
	state, err := generateRandomState()
	if err != nil {
		http.Error(w, "Failed to generate state", http.StatusInternalServerError)
		return
	}

	// Generate PKCE challenge if enabled
	var codeVerifier, codeChallenge string
	if c.config.UsePKCE {
		codeVerifier, codeChallenge, err = GenerateCodeVerifierAndChallenge()
		if err != nil {
			http.Error(w, "Failed to generate PKCE", http.StatusInternalServerError)
			return
		}
	}

	// Store state for validation later
	oauthState := &OAuthState{
		State:           state,
		CodeVerifier:    codeVerifier,
		CodeChallenge:   codeChallenge,
		RedirectURI:     c.config.RedirectURI,
		OriginalRequest: mcpClientCallback,
		CreatedAt:       time.Now(),
		ExpiresAt:       time.Now().Add(10 * time.Minute),
	}
	c.stateStore[state] = oauthState

	// Build authorization URL for third-party provider
	authURL := c.buildAuthorizationURL(state, codeChallenge)

	// Redirect user to third-party authorization page
	http.Redirect(w, r, authURL, http.StatusFound)
}

// HandleCallback handles the callback from third-party OAuth provider
// This corresponds to "Redirect to MCP Server callback" in your diagram
func (c *OAuthClient) HandleCallback(w http.ResponseWriter, r *http.Request) {
	// Extract authorization code and state
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	errorCode := r.URL.Query().Get("error")

	// Check for errors from third-party
	if errorCode != "" {
		errorDesc := r.URL.Query().Get("error_description")
		http.Error(w, fmt.Sprintf("OAuth error: %s - %s", errorCode, errorDesc), http.StatusBadRequest)
		return
	}

	if code == "" || state == "" {
		http.Error(w, "Missing code or state parameter", http.StatusBadRequest)
		return
	}

	// Validate state
	oauthState, ok := c.stateStore[state]
	if !ok {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	// Check state expiration
	if time.Now().After(oauthState.ExpiresAt) {
		delete(c.stateStore, state)
		http.Error(w, "State expired", http.StatusBadRequest)
		return
	}

	// Clean up used state
	delete(c.stateStore, state)

	// Exchange authorization code for access token from third-party
	thirdPartyToken, err := c.exchangeCodeForToken(code, oauthState.CodeVerifier)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to exchange code: %v", err), http.StatusInternalServerError)
		return
	}

	// Get user info from third-party (optional but recommended)
	userInfo, err := c.getUserInfo(thirdPartyToken.AccessToken)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get user info: %v", err), http.StatusInternalServerError)
		return
	}

	// Generate MCP-bound token
	mcpToken, err := c.generateMCPToken(userInfo, thirdPartyToken)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to generate MCP token: %v", err), http.StatusInternalServerError)
		return
	}

	// Store the mapping between MCP token and third-party token
	if err := c.storeMCPToken(r.Context(), mcpToken, thirdPartyToken, userInfo); err != nil {
		http.Error(w, "Failed to store token", http.StatusInternalServerError)
		return
	}

	// Generate MCP authorization code for the client
	mcpAuthCode, err := c.generateMCPAuthorizationCode(userInfo.Subject, mcpToken)
	if err != nil {
		http.Error(w, "Failed to generate MCP auth code", http.StatusInternalServerError)
		return
	}

	// Redirect back to MCP client with MCP authorization code
	redirectURL := c.buildMCPClientRedirect(oauthState.OriginalRequest, mcpAuthCode, state)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// exchangeCodeForToken exchanges authorization code for access token
func (c *OAuthClient) exchangeCodeForToken(code, codeVerifier string) (*ThirdPartyTokenResponse, error) {
	// Build token request
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", c.config.RedirectURI)
	data.Set("client_id", c.config.ClientID)
	data.Set("client_secret", c.config.ClientSecret)

	if c.config.UsePKCE && codeVerifier != "" {
		data.Set("code_verifier", codeVerifier)
	}

	// Make token request
	req, err := http.NewRequest(http.MethodPost, c.config.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token request failed: %d - %s", resp.StatusCode, string(body))
	}

	// Parse token response
	var tokenResp ThirdPartyTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	return &tokenResp, nil
}

// getUserInfo fetches user information from third-party
func (c *OAuthClient) getUserInfo(accessToken string) (*ThirdPartyUserInfo, error) {
	if c.config.UserInfoURL == "" {
		// No userinfo endpoint, return minimal info
		return &ThirdPartyUserInfo{
			Subject: "unknown",
			Claims:  make(map[string]interface{}),
		}, nil
	}

	req, err := http.NewRequest(http.MethodGet, c.config.UserInfoURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("userinfo request failed: %d - %s", resp.StatusCode, string(body))
	}

	// Parse userinfo response
	var userInfo ThirdPartyUserInfo
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, err
	}

	// Parse additional claims
	var claims map[string]interface{}
	if err := json.Unmarshal(body, &claims); err == nil {
		userInfo.Claims = claims
	}

	return &userInfo, nil
}

// generateMCPToken generates an MCP access token bound to third-party token
func (c *OAuthClient) generateMCPToken(userInfo *ThirdPartyUserInfo, thirdPartyToken *ThirdPartyTokenResponse) (*AccessToken, error) {
	// Use third-party user ID as subject
	scopes := ParseScopes(thirdPartyToken.Scope)

	return c.mcpTokenGen.GenerateAccessToken(
		c.config.ClientID, // MCP client ID
		userInfo.Subject,  // User ID from third-party
		scopes,
	)
}

// generateMCPAuthorizationCode generates an MCP authorization code
func (c *OAuthClient) generateMCPAuthorizationCode(userID string, mcpToken *AccessToken) (string, error) {
	code, err := GenerateAuthorizationCode()
	if err != nil {
		return "", err
	}

	// Store authorization code in your store
	authCode := &AuthorizationCode{
		Code:      code,
		ClientID:  c.config.ClientID,
		UserID:    userID,
		Scopes:    mcpToken.Scopes,
		ExpiresAt: time.Now().Add(5 * time.Minute),
		CreatedAt: time.Now(),
		Used:      false,
	}

	if err := c.store.SaveAuthorizationCode(context.Background(), authCode); err != nil {
		return "", err
	}

	return code, nil
}

// storeMCPToken stores the MCP token and its relationship to third-party token
func (c *OAuthClient) storeMCPToken(ctx context.Context, mcpToken *AccessToken, thirdPartyToken *ThirdPartyTokenResponse, userInfo *ThirdPartyUserInfo) error {
	// Store third-party token info in metadata
	mcpToken.Metadata = map[string]interface{}{
		"third_party_provider": c.config.ProviderName,
		"third_party_token":    thirdPartyToken.AccessToken,
		"third_party_refresh":  thirdPartyToken.RefreshToken,
		"third_party_expires":  time.Now().Add(time.Duration(thirdPartyToken.ExpiresIn) * time.Second).Unix(),
		"user_email":           userInfo.Email,
		"user_name":            userInfo.Name,
	}

	return c.store.SaveAccessToken(ctx, mcpToken)
}

// buildAuthorizationURL builds the third-party authorization URL
func (c *OAuthClient) buildAuthorizationURL(state, codeChallenge string) string {
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", c.config.ClientID)
	params.Set("redirect_uri", c.config.RedirectURI)
	params.Set("state", state)
	params.Set("scope", strings.Join(c.config.Scopes, " "))

	if c.config.UsePKCE && codeChallenge != "" {
		params.Set("code_challenge", codeChallenge)
		params.Set("code_challenge_method", "S256")
	}

	return c.config.AuthorizationURL + "?" + params.Encode()
}

// buildMCPClientRedirect builds redirect URL back to MCP client
func (c *OAuthClient) buildMCPClientRedirect(mcpClientCallback, authCode, state string) string {
	redirectURL, _ := url.Parse(mcpClientCallback)
	query := redirectURL.Query()
	query.Set("code", authCode)
	query.Set("state", state)
	redirectURL.RawQuery = query.Encode()
	return redirectURL.String()
}

// generateRandomState generates a cryptographically secure random state
func generateRandomState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
