package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	clientID    = "mcp-client-demo"
	redirectURI = "http://localhost:9999/callback"
	authURL     = "http://localhost:8080/oauth/authorize"
	tokenURL    = "http://localhost:8080/oauth/token"
)

func main() {
	log.Println("🚀 Starting MCP Client Example...")

	// 1. Generate PKCE parameters
	codeVerifier, codeChallenge := generatePKCE()
	log.Printf("🔐 Generated PKCE: verifier=%s... challenge=%s...",
		codeVerifier[:10], codeChallenge[:10])

	// 2. Start a local callback server
	authCodeChan := make(chan string, 1)
	go startCallbackServer(authCodeChan)

	time.Sleep(500 * time.Millisecond) // Wait for the server to start

	// 3. Build the authorization URL
	state := generateState()
	authorizeURL := buildAuthorizeURL(codeChallenge, state)

	log.Println("\n📋 Step 1: Open this URL in browser (or auto-requesting):")
	log.Printf("   %s\n", authorizeURL)

	go func() {
		resp, err := http.Get(authorizeURL)
		if err != nil {
			log.Printf("❌ Auto-request failed: %v", err)
			return
		}
		defer resp.Body.Close()
		log.Printf("✅ Authorization redirected to callback")
	}()

	// 5. Wait for the authorization code
	log.Println("\n⏳ Waiting for authorization code...")
	authCode := <-authCodeChan
	log.Printf("✅ Received authorization code: %s...\n", authCode[:20])

	// 6. Exchange authorization code for access token
	accessToken, refreshToken := exchangeToken(authCode, codeVerifier)

	log.Println("\n🎉 OAuth Flow Complete!")
	log.Printf("   Access Token:  %s...", accessToken[:30])
	log.Printf("   Refresh Token: %s...", refreshToken[:30])

	// 7. Simulate MCP tool calls (simplified, actual calls require SSE connection)
	log.Println("\n📞 Simulating MCP tool calls with access token...")
	testToolAccess(accessToken)

	log.Println("\n✅ Example completed! Press Ctrl+C to exit.")
	select {} // Keep the program running
}

// generatePKCE creates PKCE parameters (verifier and challenge)
func generatePKCE() (verifier, challenge string) {
	b := make([]byte, 32)
	rand.Read(b)
	verifier = base64.RawURLEncoding.EncodeToString(b)

	h := sha256.New()
	h.Write([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	return verifier, challenge
}

// generateState creates a random state value to protect against CSRF attacks
func generateState() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// buildAuthorizeURL constructs the full OAuth 2.1 authorization URL
func buildAuthorizeURL(codeChallenge, state string) string {
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", clientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("scope", "read write") // Request read and write permissions
	params.Set("state", state)
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", "S256")

	return authURL + "?" + params.Encode()
}

// startCallbackServer starts a local HTTP server to receive the authorization callback
func startCallbackServer(authCodeChan chan string) {
	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")

		if code == "" {
			http.Error(w, "Missing authorization code", http.StatusBadRequest)
			return
		}

		log.Printf("✅ Callback received: code=%s... state=%s", code[:20], state)

		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `
			<html>
			<body>
				<h2>✅ Authorization Successful!</h2>
				<p>You can close this window and return to the terminal.</p>
			</body>
			</html>
		`)

		authCodeChan <- code
	})

	log.Println("🌐 Callback server listening on http://localhost:9999/callback")
	http.ListenAndServe(":9999", nil)
}

// exchangeToken exchanges the authorization code for access and refresh tokens
func exchangeToken(code, codeVerifier string) (accessToken, refreshToken string) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("client_id", clientID)
	data.Set("code_verifier", codeVerifier)

	resp, err := http.Post(tokenURL, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		log.Fatalf("❌ Token exchange failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("❌ Token endpoint error: %s", string(body))
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
	}

	json.Unmarshal(body, &tokenResp)

	return tokenResp.AccessToken, tokenResp.RefreshToken
}

// testToolAccess simulates MCP tool access (simplified for demo)
func testToolAccess(accessToken string) {
	log.Println("  ℹ️  Note: Full MCP tool calls require SSE transport")
	log.Println("  ℹ️  This demo only shows that the token was obtained successfully")
	log.Printf("  ℹ️  Use this token in MCP Client: Authorization: Bearer %s...", accessToken[:20])
}
