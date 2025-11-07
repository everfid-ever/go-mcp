package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// TokenGenerator handles token generation and validation
type TokenGenerator struct {
	// JWT signing key
	SigningKey []byte
	// Issuer identifier
	Issuer string
	// Key ID for JWKS
	KeyID string
	// Token expiration times
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	// Token rotation settings
	RotateRefreshTokens bool
}

// TokenClaims represents JWT claims for access tokens
type TokenClaims struct {
	jwt.RegisteredClaims
	ClientID string   `json:"client_id,omitempty"`
	Scopes   []string `json:"scopes,omitempty"`
	TokenID  string   `json:"jti,omitempty"`
}

// NewTokenGenerator creates a new token generator with default settings
func NewTokenGenerator(signingKey []byte, issuer string) *TokenGenerator {
	return &TokenGenerator{
		SigningKey:          signingKey,
		Issuer:              issuer,
		KeyID:               GenerateKeyID(signingKey),
		AccessTokenTTL:      15 * time.Minute,    // OAuth 2.1 recommendation
		RefreshTokenTTL:     30 * 24 * time.Hour, // 30 days
		RotateRefreshTokens: true,                // OAuth 2.1 best practice
	}
}

// GenerateRandomToken generates a cryptographically secure random token
func GenerateRandomToken(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// GenerateAccessToken generates a new JWT access token with resource indicators
func (g *TokenGenerator) GenerateAccessToken(clientID, userID string, scopes []string, resources []string) (*AccessToken, error) {
	now := time.Now()
	expiresAt := now.Add(g.AccessTokenTTL)

	// Generate token ID for tracking
	tokenID, err := GenerateRandomToken(16)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token ID: %w", err)
	}

	// RFC 8707: Set audience to resource indicators
	audience := jwt.ClaimStrings{clientID}
	if len(resources) > 0 {
		audience = make(jwt.ClaimStrings, len(resources))
		copy(audience, resources)
	}

	// Create JWT claims
	claims := TokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    g.Issuer,
			Subject:   userID,
			Audience:  audience,
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        tokenID,
		},
		ClientID: clientID,
		Scopes:   scopes,
		TokenID:  tokenID,
	}

	// Create and sign token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = g.KeyID // Add Key ID to header

	tokenString, err := token.SignedString(g.SigningKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign token: %w", err)
	}

	return &AccessToken{
		Token:     tokenString,
		TokenType: TokenTypeBearer,
		ClientID:  clientID,
		UserID:    userID,
		Scopes:    scopes,
		Resources: resources,
		ExpiresAt: expiresAt,
		CreatedAt: now,
	}, nil
}

// GenerateRefreshToken generates a new refresh token
func (g *TokenGenerator) GenerateRefreshToken(clientID, userID string, scopes []string, resources []string) (*RefreshToken, error) {
	now := time.Now()
	expiresAt := now.Add(g.RefreshTokenTTL)

	// Generate opaque token
	tokenString, err := GenerateRandomToken(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &RefreshToken{
		Token:         tokenString,
		ClientID:      clientID,
		UserID:        userID,
		Scopes:        scopes,
		Resources:     resources,
		ExpiresAt:     expiresAt,
		CreatedAt:     now,
		RotationCount: 0,
		Revoked:       false,
	}, nil
}

// GenerateAuthorizationCode generates a new authorization code
func GenerateAuthorizationCode() (string, error) {
	return GenerateRandomToken(32)
}

// ValidateAccessToken validates and parses a JWT access token
func (g *TokenGenerator) ValidateAccessToken(tokenString string) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return g.SigningKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*TokenClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Verify issuer
	if claims.Issuer != g.Issuer {
		return nil, fmt.Errorf("invalid issuer")
	}

	return claims, nil
}

// ValidateTokenAudience validates that the token's audience matches the requested resource
func (g *TokenGenerator) ValidateTokenAudience(claims *TokenClaims, resource string) error {
	if resource == "" {
		return nil // No specific resource requested
	}

	for _, aud := range claims.Audience {
		if aud == resource {
			return nil
		}
	}

	return fmt.Errorf("token audience does not include requested resource: %s", resource)
}

// CreateTokenResponse creates a token response for the client
func CreateTokenResponse(accessToken *AccessToken, refreshToken *RefreshToken) *TokenResponse {
	response := &TokenResponse{
		AccessToken: accessToken.Token,
		TokenType:   string(accessToken.TokenType),
		ExpiresIn:   int64(time.Until(accessToken.ExpiresAt).Seconds()),
	}

	if refreshToken != nil {
		response.RefreshToken = refreshToken.Token
	}

	if len(accessToken.Scopes) > 0 {
		response.Scope = strings.Join(accessToken.Scopes, " ")
	}

	return response
}
