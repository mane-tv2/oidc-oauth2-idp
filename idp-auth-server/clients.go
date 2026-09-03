package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Supported values a dynamically registered client may ask for. Registration is
// rejected when a client requests anything outside these sets.
var (
	supportedGrantTypes             = []string{"authorization_code", "refresh_token"}
	supportedResponseTypes          = []string{"code"}
	supportedTokenEndpointAuthAlgos = []string{"client_secret_basic", "client_secret_post", "none"}
)

const defaultRegistrationScope = "openid profile email"

// registeredClient is a client created through RFC 7591 dynamic client
// registration. Registrations are in-memory only and lost on restart.
// FIXME: ClientSecret is stored in plaintext; hash it if this ever leaves demo use.
type registeredClient struct {
	ClientID                string
	ClientSecret            string
	ClientName              string
	RedirectURIs            []string
	GrantTypes              []string
	ResponseTypes           []string
	Scope                   string
	TokenEndpointAuthMethod string
	CreatedAt               time.Time
}

// clientMetadata is the RFC 7591 client metadata document, used both for the
// registration request and the registration response.
type clientMetadata struct {
	ClientName              string   `json:"client_name,omitempty"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
}

type registrationResponse struct {
	ClientID              string `json:"client_id"`
	ClientSecret          string `json:"client_secret,omitempty"`
	ClientIDIssuedAt      int64  `json:"client_id_issued_at"`
	ClientSecretExpiresAt int64  `json:"client_secret_expires_at,omitempty"`
	clientMetadata
}

// registrationError is an RFC 7591 section 3.2.2 error response.
type registrationError struct {
	code        string
	description string
}

func (e *registrationError) Error() string {
	return e.code + ": " + e.description
}

func invalidClientMetadata(format string, args ...any) *registrationError {
	return &registrationError{code: "invalid_client_metadata", description: fmt.Sprintf(format, args...)}
}

func invalidRedirectURI(format string, args ...any) *registrationError {
	return &registrationError{code: "invalid_redirect_uri", description: fmt.Sprintf(format, args...)}
}

// register implements RFC 7591 dynamic client registration. Registration is
// open (unauthenticated) so that MCP clients can self-register.
// FIXME: Registered clients are not yet enforced at /authorize or /token.
func (s *server) register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	logRequest(s.log(), "register", r)

	if ct := r.Header.Get("Content-Type"); ct != "" {
		if mediaType := strings.TrimSpace(strings.Split(ct, ";")[0]); mediaType != "application/json" {
			writeRegistrationError(w, invalidClientMetadata("expected Content-Type application/json, got %q", mediaType))
			return
		}
	}

	var requested clientMetadata
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&requested); err != nil {
		writeRegistrationError(w, invalidClientMetadata("could not parse client metadata: %v", err))
		return
	}

	normalized, err := normalizeClientMetadata(requested)
	if err != nil {
		writeRegistrationError(w, err)
		return
	}

	client := registeredClient{
		ClientID:                uuid.NewString(),
		ClientName:              normalized.ClientName,
		RedirectURIs:            normalized.RedirectURIs,
		GrantTypes:              normalized.GrantTypes,
		ResponseTypes:           normalized.ResponseTypes,
		Scope:                   normalized.Scope,
		TokenEndpointAuthMethod: normalized.TokenEndpointAuthMethod,
		CreatedAt:               time.Now().UTC(),
	}

	// Public clients (token_endpoint_auth_method "none") authenticate with PKCE
	// only and get no secret.
	if client.TokenEndpointAuthMethod != "none" {
		secret, err := generateClientSecret()
		if err != nil {
			s.log().Error("could not generate client secret", "error", err.Error())
			writeOAuthError(w, http.StatusInternalServerError, "server_error")
			return
		}
		client.ClientSecret = secret
	}

	s.mu.Lock()
	s.clients[client.ClientID] = client
	s.mu.Unlock()

	s.log().Info("client registered",
		"client_id", client.ClientID,
		"client_name", client.ClientName,
		"token_endpoint_auth_method", client.TokenEndpointAuthMethod)

	response := registrationResponse{
		ClientID:              client.ClientID,
		ClientSecret:          client.ClientSecret,
		ClientIDIssuedAt:      client.CreatedAt.Unix(),
		ClientSecretExpiresAt: 0,
		clientMetadata:        normalized,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(response)
}

// normalizeClientMetadata applies defaults and validates the requested metadata.
func normalizeClientMetadata(in clientMetadata) (clientMetadata, *registrationError) {
	out := clientMetadata{
		ClientName:              strings.TrimSpace(in.ClientName),
		GrantTypes:              dedupeStrings(in.GrantTypes),
		ResponseTypes:           dedupeStrings(in.ResponseTypes),
		Scope:                   strings.TrimSpace(in.Scope),
		TokenEndpointAuthMethod: strings.TrimSpace(in.TokenEndpointAuthMethod),
	}

	if len(out.GrantTypes) == 0 {
		out.GrantTypes = []string{"authorization_code"}
	}
	if len(out.ResponseTypes) == 0 {
		out.ResponseTypes = []string{"code"}
	}
	if out.Scope == "" {
		out.Scope = defaultRegistrationScope
	}
	if out.TokenEndpointAuthMethod == "" {
		out.TokenEndpointAuthMethod = "client_secret_basic"
	}

	for _, grantType := range out.GrantTypes {
		if !containsString(supportedGrantTypes, grantType) {
			return clientMetadata{}, invalidClientMetadata("unsupported grant_type %q (supported: %s)",
				grantType, strings.Join(supportedGrantTypes, ", "))
		}
	}
	for _, responseType := range out.ResponseTypes {
		if !containsString(supportedResponseTypes, responseType) {
			return clientMetadata{}, invalidClientMetadata("unsupported response_type %q (supported: %s)",
				responseType, strings.Join(supportedResponseTypes, ", "))
		}
	}
	if !containsString(supportedTokenEndpointAuthAlgos, out.TokenEndpointAuthMethod) {
		return clientMetadata{}, invalidClientMetadata("unsupported token_endpoint_auth_method %q (supported: %s)",
			out.TokenEndpointAuthMethod, strings.Join(supportedTokenEndpointAuthAlgos, ", "))
	}

	redirectURIs, err := normalizeRedirectURIs(in.RedirectURIs)
	if err != nil {
		return clientMetadata{}, err
	}
	if len(redirectURIs) == 0 && containsString(out.GrantTypes, "authorization_code") {
		return clientMetadata{}, invalidRedirectURI("redirect_uris is required for the authorization_code grant")
	}
	out.RedirectURIs = redirectURIs

	return out, nil
}

func normalizeRedirectURIs(in []string) ([]string, *registrationError) {
	out := make([]string, 0, len(in))
	for _, raw := range dedupeStrings(in) {
		redirectURI := strings.TrimSpace(raw)
		if redirectURI == "" {
			return nil, invalidRedirectURI("redirect_uris must not contain empty values")
		}
		parsed, err := url.Parse(redirectURI)
		if err != nil {
			return nil, invalidRedirectURI("redirect_uri %q is not a valid URI: %v", redirectURI, err)
		}
		if !parsed.IsAbs() {
			return nil, invalidRedirectURI("redirect_uri %q must be an absolute URI", redirectURI)
		}
		if parsed.Fragment != "" || strings.Contains(redirectURI, "#") {
			return nil, invalidRedirectURI("redirect_uri %q must not contain a fragment", redirectURI)
		}
		out = append(out, redirectURI)
	}
	return out, nil
}

func generateClientSecret() (string, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(secret), nil
}

func writeRegistrationError(w http.ResponseWriter, regErr *registrationError) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             regErr.code,
		"error_description": regErr.description,
	})
}

func containsString(haystack []string, needle string) bool {
	for _, item := range haystack {
		if item == needle {
			return true
		}
	}
	return false
}

// registeredClientViews renders the registry for the dashboard, newest first.
// The client secret is deliberately never exposed here.
func (s *server) registeredClientViewsLocked() []registeredClientView {
	views := make([]registeredClientView, 0, len(s.clients))
	for _, client := range s.clients {
		views = append(views, registeredClientView{
			ClientID:                client.ClientID,
			ClientName:              client.ClientName,
			CreatedAt:               client.CreatedAt.Format(time.RFC3339),
			RedirectURIs:            client.RedirectURIs,
			GrantTypes:              client.GrantTypes,
			Scope:                   client.Scope,
			TokenEndpointAuthMethod: client.TokenEndpointAuthMethod,
			Confidential:            client.ClientSecret != "",
		})
	}
	sort.Slice(views, func(i, j int) bool {
		if views[i].CreatedAt == views[j].CreatedAt {
			return views[i].ClientID < views[j].ClientID
		}
		return views[i].CreatedAt > views[j].CreatedAt
	})
	return views
}
