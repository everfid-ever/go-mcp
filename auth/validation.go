package auth

import (
	"fmt"
	"net/url"
	"strings"
)

// validateRedirectURI validates that the redirect URI exactly matches one of the registered URIs
// OAuth 2.1 requires exact matching, no wildcards allowed
func validateRedirectURI(allowedURIs []string, requestedURI string) error {
	if requestedURI == "" {
		return fmt.Errorf("redirect_uri is required")
	}

	for _, allowed := range allowedURIs {
		if allowed == requestedURI {
			return nil
		}
	}

	return fmt.Errorf("%s: redirect_uri not registered for this client", ErrInvalidRequest)
}

// validateEndpointSecurity ensures HTTPS is used (except for localhost)
// OAuth 2.1 requirement: All endpoints must use HTTPS except localhost for development
func validateEndpointSecurity(uri string) error {
	if uri == "" {
		return fmt.Errorf("URI cannot be empty")
	}

	parsedURL, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("invalid URI: %w", err)
	}

	// OAuth 2.1 requires HTTPS except for localhost
	if parsedURL.Scheme != "https" {
		if !isLocalhost(parsedURL.Host) {
			return fmt.Errorf("%s: HTTPS required for non-localhost endpoints", ErrInvalidRequest)
		}
	}

	// Fragment components are not allowed in redirect URIs
	if parsedURL.Fragment != "" {
		return fmt.Errorf("%s: redirect URIs must not contain fragment components", ErrInvalidRequest)
	}

	return nil
}

// isLocalhost checks if a host is localhost or 127.0.0.1
func isLocalhost(host string) bool {
	// Remove port if present
	hostWithoutPort := host
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		hostWithoutPort = host[:idx]
	}

	return hostWithoutPort == "localhost" ||
		hostWithoutPort == "127.0.0.1" ||
		hostWithoutPort == "[::1]" ||
		hostWithoutPort == "::1"
}

// validateState ensures state parameter is present (CSRF protection)
// OAuth 2.1 strongly recommends state parameter for all authorization requests
func validateState(state string) error {
	if state == "" {
		return fmt.Errorf("%s: state parameter is required for CSRF protection", ErrInvalidRequest)
	}

	// State should be at least 8 characters for adequate entropy
	if len(state) < 8 {
		return fmt.Errorf("%s: state parameter too short (minimum 8 characters)", ErrInvalidRequest)
	}

	return nil
}

// validateScope validates requested scopes
func validateScope(requestedScopes []string, allowedScopes []string) error {
	if len(requestedScopes) == 0 {
		return nil // Empty scope is allowed
	}

	allowedMap := make(map[string]bool)
	for _, scope := range allowedScopes {
		allowedMap[scope] = true
	}

	for _, requested := range requestedScopes {
		if !allowedMap[requested] {
			return fmt.Errorf("%s: scope '%s' is not allowed", ErrInvalidScope, requested)
		}
	}

	return nil
}

// validateClientRedirectURIs validates all redirect URIs for a client during registration
func validateClientRedirectURIs(redirectURIs []string, applicationType string) error {
	if len(redirectURIs) == 0 {
		return fmt.Errorf("%s: at least one redirect_uri is required", ErrInvalidRequest)
	}

	for _, uri := range redirectURIs {
		if err := validateRedirectURIFormat(uri, applicationType); err != nil {
			return err
		}
	}

	return nil
}

// validateRedirectURIFormat validates the format of a redirect URI based on application type
func validateRedirectURIFormat(uri string, applicationType string) error {
	parsedURL, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("%s: invalid redirect URI format: %w", ErrInvalidRequest, err)
	}

	// Fragment components are forbidden
	if parsedURL.Fragment != "" {
		return fmt.Errorf("%s: redirect URIs must not contain fragment components", ErrInvalidRequest)
	}

	switch applicationType {
	case "web":
		// Web clients must use HTTPS (except localhost for development)
		if parsedURL.Scheme != "https" && !isLocalhost(parsedURL.Host) {
			return fmt.Errorf("%s: web clients must use HTTPS redirect URIs (except localhost)", ErrInvalidRequest)
		}
	case "native":
		// Native clients can use custom schemes or localhost HTTP
		if parsedURL.Scheme == "http" {
			if !isLocalhost(parsedURL.Host) {
				return fmt.Errorf("%s: native clients cannot use http:// URIs except localhost", ErrInvalidRequest)
			}
		}
		// Custom schemes are allowed for native apps
	default:
		return fmt.Errorf("%s: unsupported application type: %s", ErrInvalidRequest, applicationType)
	}

	return nil
}

// parseScopes parses a space-separated scope string into a slice
func parseScopes(scopeString string) []string {
	if scopeString == "" {
		return []string{}
	}

	scopes := strings.Split(scopeString, " ")
	result := make([]string, 0, len(scopes))

	for _, scope := range scopes {
		trimmed := strings.TrimSpace(scope)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}

	return result
}
