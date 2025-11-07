package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
)

// JWK represents a JSON Web Key
type JWK struct {
	Kty string `json:"kty"`           // Key Type
	Use string `json:"use,omitempty"` // Public Key Use
	Kid string `json:"kid,omitempty"` // Key ID
	Alg string `json:"alg,omitempty"` // Algorithm
	N   string `json:"n,omitempty"`   // RSA Modulus (for RSA keys)
	E   string `json:"e,omitempty"`   // RSA Exponent (for RSA keys)
	K   string `json:"k,omitempty"`   // Symmetric key (for oct keys)
}

// JWKSet represents a JSON Web Key Set
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// JWKSProvider manages JWKS endpoint
type JWKSProvider struct {
	signingKey []byte
	keyID      string
	jwks       *JWKSet
}

// NewJWKSProvider creates a new JWKS provider
func NewJWKSProvider(signingKey []byte, keyID string) *JWKSProvider {
	provider := &JWKSProvider{
		signingKey: signingKey,
		keyID:      keyID,
	}
	provider.generateJWKS()
	return provider
}

// generateJWKS creates the JWKS document
func (jp *JWKSProvider) generateJWKS() {
	// For HMAC (HS256), we typically don't expose the symmetric key
	// This is a placeholder - in production with RS256, you'd expose the public key
	jp.jwks = &JWKSet{
		Keys: []JWK{
			{
				Kty: "oct",
				Use: "sig",
				Kid: jp.keyID,
				Alg: "HS256",
				// Note: Symmetric keys should NOT be exposed in JWKS
				// This is here for documentation purposes only
				// In production, use RS256/ES256 with public/private key pairs
			},
		},
	}
}

// GetJWKS returns the JWKS document
func (jp *JWKSProvider) GetJWKS() *JWKSet {
	return jp.jwks
}

// ServeHTTP handles the JWKS endpoint
func (jp *JWKSProvider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	json.NewEncoder(w).Encode(jp.jwks)
}

// GenerateKeyID creates a key ID from the signing key
func GenerateKeyID(signingKey []byte) string {
	h := hmac.New(sha256.New, []byte("key-id-salt"))
	h.Write(signingKey)
	hash := h.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(hash[:16])
}
