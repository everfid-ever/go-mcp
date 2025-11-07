package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/ThinkInAIXYZ/go-mcp/auth"
	"github.com/ThinkInAIXYZ/go-mcp/auth/memory"
	"github.com/ThinkInAIXYZ/go-mcp/protocol"
	"github.com/ThinkInAIXYZ/go-mcp/server"
	"github.com/ThinkInAIXYZ/go-mcp/transport"
)

func main() {
	// 1. Create an in-memory storage backend
	store := memory.NewStore()

	// 2. JWT signing secret (must be at least 32 bytes)
	jwtSecret := []byte("example-secret-key-must-be-at-least-32-bytes-long!!")

	// 3. Create the OAuth Server (with PKCE enabled)
	serverConfig := auth.DefaultServerConfig("mcp-example-server")
	serverConfig.RequirePKCE = true
	serverConfig.RequireS256 = true

	authServer, err := auth.NewServer(store, jwtSecret, serverConfig)
	if err != nil {
		log.Fatalf("Failed to create auth server: %v", err)
	}

	// 4. Pre-register an MCP Client (simulating Claude Desktop)
	client := &auth.Client{
		ID:           "mcp-client-demo",
		Name:         "MCP Client Demo",
		RedirectURIs: []string{"http://localhost:9999/callback"},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		Scopes:       []string{"read", "write", "admin"},
		IsPublic:     true, // Public client (desktop app, CLI, etc.)
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := store.CreateClient(context.Background(), client); err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	log.Printf("✅ Registered client: %s", client.ID)

	// 5. Create an HTTP handler for OAuth endpoints
	handler := auth.NewHandler(authServer)

	// 6. Register OAuth endpoints
	mux := http.NewServeMux()

	// Standard OAuth endpoints
	mux.HandleFunc("/.well-known/oauth-authorization-server", handleMetadata)
	mux.HandleFunc("/oauth/authorize", handleAuthorizeSimple(authServer))
	mux.HandleFunc("/oauth/token", handler.HandleToken)
	mux.HandleFunc("/oauth/introspect", handler.HandleIntrospection)
	mux.HandleFunc("/oauth/revoke", handler.HandleRevocation)

	// Start the OAuth HTTP server
	go func() {
		log.Println("🔐 OAuth Server started")
		log.Println("   Discovery: http://localhost:8080/.well-known/oauth-authorization-server")
		log.Println("   Authorize: http://localhost:8080/oauth/authorize")
		log.Println("   Token:     http://localhost:8080/oauth/token")
		if err := http.ListenAndServe(":8080", mux); err != nil {
			log.Fatalf("OAuth server error: %v", err)
		}
	}()

	// 7. Create the MCP Server
	t, _ := transport.NewSSEServerTransport("127.0.0.1:9090")

	mcpServer, _ := server.NewServer(t,
		server.WithServerInfo(protocol.Implementation{
			Name:    "simple-oauth-example",
			Version: "1.0.0",
		}),
		server.WithAuth(authServer, map[string][]string{
			"read_data":   {"read"},
			"write_data":  {"write"},
			"delete_data": {"admin"},
		}),
	)

	// 8. Register MCP tools
	registerTools(mcpServer)

	log.Println("🚀 MCP Server started on http://localhost:9090/sse")
	log.Println("\n👉 Run the client: go run client.go\n")
	mcpServer.Run()
}

// handleMetadata returns OAuth 2.1 authorization server metadata
func handleMetadata(w http.ResponseWriter, r *http.Request) {
	metadata := map[string]interface{}{
		"issuer":                                        "mcp-example-server",
		"authorization_endpoint":                        "http://localhost:8080/oauth/authorize",
		"token_endpoint":                                "http://localhost:8080/oauth/token",
		"revocation_endpoint":                           "http://localhost:8080/oauth/revoke",
		"introspection_endpoint":                        "http://localhost:8080/oauth/introspect",
		"response_types_supported":                      []string{"code"},
		"grant_types_supported":                         []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":              []string{"S256"},
		"token_endpoint_auth_methods_supported":         []string{"none"}, // Public clients only
		"revocation_endpoint_auth_methods_supported":    []string{"none"},
		"introspection_endpoint_auth_methods_supported": []string{"client_secret_basic"},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `%v`, toJSON(metadata))
}

// handleAuthorizeSimple provides a simplified authorization endpoint (auto-approved)
func handleAuthorizeSimple(authServer *auth.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse authorization request
		req := &auth.AuthorizationRequest{
			ResponseType:        r.URL.Query().Get("response_type"),
			ClientID:            r.URL.Query().Get("client_id"),
			RedirectURI:         r.URL.Query().Get("redirect_uri"),
			Scope:               r.URL.Query().Get("scope"),
			State:               r.URL.Query().Get("state"),
			CodeChallenge:       r.URL.Query().Get("code_challenge"),
			CodeChallengeMethod: r.URL.Query().Get("code_challenge_method"),
		}

		log.Printf("📝 Authorization request: client=%s, scope=%s", req.ClientID, req.Scope)

		// ✅ Key point: Automatically approve the request, using client_id as userID
		// In a real implementation, you could:
		// 1. Extract user_id from the request parameters
		// 2. Retrieve it from an external authentication system
		// 3. Use an anonymous or demo user
		userID := req.ClientID + "-user" // Example: bind a virtual user to each client

		// Generate authorization code and redirect
		redirectURL, err := authServer.HandleAuthorizationRequest(r.Context(), req, userID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		log.Printf("✅ Authorization granted for user: %s", userID)
		http.Redirect(w, r, redirectURL, http.StatusFound)
	}
}

// registerTools registers sample MCP tools with different scope requirements
func registerTools(s *server.Server) {
	// Tool 1: Read data (requires "read" scope)
	readTool, _ := protocol.NewTool("read_data", "Read data from server", struct {
		Key string `json:"key" description:"Data key to read"`
	}{})

	s.RegisterTool(readTool, func(ctx context.Context, req *protocol.CallToolRequest) (*protocol.CallToolResult, error) {
		userID := auth.GetUserID(ctx)
		scopes := auth.GetScopes(ctx)

		return &protocol.CallToolResult{
			Content: []protocol.Content{
				&protocol.TextContent{
					Text: fmt.Sprintf("✅ Read data (user: %s, scopes: %v)", userID, scopes),
				},
			},
		}, nil
	})

	// Tool 2: Write data (requires "write" scope)
	writeTool, _ := protocol.NewTool("write_data", "Write data to server", struct {
		Key   string `json:"key" description:"Data key"`
		Value string `json:"value" description:"Data value"`
	}{})

	s.RegisterTool(writeTool, func(ctx context.Context, req *protocol.CallToolRequest) (*protocol.CallToolResult, error) {
		userID := auth.GetUserID(ctx)
		scopes := auth.GetScopes(ctx)

		return &protocol.CallToolResult{
			Content: []protocol.Content{
				&protocol.TextContent{
					Text: fmt.Sprintf("✅ Write data (user: %s, scopes: %v)", userID, scopes),
				},
			},
		}, nil
	})

	// Tool 3: Delete data (requires "admin" scope)
	deleteTool, _ := protocol.NewTool("delete_data", "Delete data from server", struct {
		Key string `json:"key" description:"Data key to delete"`
	}{})

	s.RegisterTool(deleteTool, func(ctx context.Context, req *protocol.CallToolRequest) (*protocol.CallToolResult, error) {
		userID := auth.GetUserID(ctx)
		scopes := auth.GetScopes(ctx)

		return &protocol.CallToolResult{
			Content: []protocol.Content{
				&protocol.TextContent{
					Text: fmt.Sprintf("✅ Delete data (user: %s, scopes: %v)", userID, scopes),
				},
			},
		}, nil
	})
}

// toJSON converts an object to a JSON-like string (simplified for demo)
func toJSON(v interface{}) string {
	return fmt.Sprintf("%v", v)
}
