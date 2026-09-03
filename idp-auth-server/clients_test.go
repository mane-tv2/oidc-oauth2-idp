package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newRegistrationTestServer() *server {
	return &server{
		clients:     map[string]registeredClient{},
		externalURL: "https://idp.example.com",
		subjectType: "public",
	}
}

func postRegistration(t *testing.T, srv *server, body string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.register(rec, req)
	return rec
}

func decodeRegistrationBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()

	out := map[string]any{}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response body %q: %v", rec.Body.String(), err)
	}
	return out
}

func TestRegisterConfidentialClient(t *testing.T) {
	t.Parallel()

	srv := newRegistrationTestServer()
	rec := postRegistration(t, srv, `{
		"client_name": "Demo RP",
		"redirect_uris": ["https://rp.example.com/callback"]
	}`)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("expected Cache-Control no-store, got %q", got)
	}

	body := decodeRegistrationBody(t, rec)
	clientID, _ := body["client_id"].(string)
	if clientID == "" {
		t.Fatalf("expected a client_id in %v", body)
	}
	if secret, _ := body["client_secret"].(string); secret == "" {
		t.Fatalf("expected a client_secret for a confidential client")
	}
	if body["token_endpoint_auth_method"] != "client_secret_basic" {
		t.Fatalf("expected default token_endpoint_auth_method, got %v", body["token_endpoint_auth_method"])
	}
	if body["scope"] != defaultRegistrationScope {
		t.Fatalf("expected default scope, got %v", body["scope"])
	}
	if _, ok := body["client_id_issued_at"]; !ok {
		t.Fatalf("expected client_id_issued_at in %v", body)
	}

	stored, ok := srv.clients[clientID]
	if !ok {
		t.Fatalf("expected client %q to be stored", clientID)
	}
	if stored.ClientName != "Demo RP" {
		t.Fatalf("expected stored client name, got %q", stored.ClientName)
	}
	if stored.CreatedAt.IsZero() {
		t.Fatalf("expected a registration timestamp")
	}
	if len(stored.GrantTypes) != 1 || stored.GrantTypes[0] != "authorization_code" {
		t.Fatalf("expected default grant types, got %v", stored.GrantTypes)
	}
}

func TestRegisterPublicClientGetsNoSecret(t *testing.T) {
	t.Parallel()

	srv := newRegistrationTestServer()
	rec := postRegistration(t, srv, `{
		"client_name": "MCP Client",
		"redirect_uris": ["http://127.0.0.1:33418/callback"],
		"grant_types": ["authorization_code", "refresh_token"],
		"token_endpoint_auth_method": "none"
	}`)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	body := decodeRegistrationBody(t, rec)
	if _, present := body["client_secret"]; present {
		t.Fatalf("did not expect a client_secret for a public client: %v", body)
	}

	clientID, _ := body["client_id"].(string)
	if srv.clients[clientID].ClientSecret != "" {
		t.Fatalf("did not expect a stored client secret for a public client")
	}
}

func TestRegisterRejectsMissingRedirectURIs(t *testing.T) {
	t.Parallel()

	srv := newRegistrationTestServer()
	rec := postRegistration(t, srv, `{"client_name": "No Redirects"}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	if body := decodeRegistrationBody(t, rec); body["error"] != "invalid_redirect_uri" {
		t.Fatalf("expected invalid_redirect_uri, got %v", body)
	}
	if len(srv.clients) != 0 {
		t.Fatalf("expected no client to be stored")
	}
}

func TestRegisterRejectsInvalidRedirectURIs(t *testing.T) {
	t.Parallel()

	testCases := map[string]string{
		"relative": `{"redirect_uris": ["/callback"]}`,
		"fragment": `{"redirect_uris": ["https://rp.example.com/callback#frag"]}`,
		"empty":    `{"redirect_uris": [""]}`,
	}

	for name, body := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := newRegistrationTestServer()
			rec := postRegistration(t, srv, body)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
			}
			if got := decodeRegistrationBody(t, rec); got["error"] != "invalid_redirect_uri" {
				t.Fatalf("expected invalid_redirect_uri, got %v", got)
			}
		})
	}
}

func TestRegisterRejectsUnsupportedMetadata(t *testing.T) {
	t.Parallel()

	testCases := map[string]string{
		"grant type":     `{"redirect_uris": ["https://rp.example.com/cb"], "grant_types": ["client_credentials"]}`,
		"response type":  `{"redirect_uris": ["https://rp.example.com/cb"], "response_types": ["token"]}`,
		"auth method":    `{"redirect_uris": ["https://rp.example.com/cb"], "token_endpoint_auth_method": "private_key_jwt"}`,
		"malformed json": `{"redirect_uris":`,
	}

	for name, body := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := newRegistrationTestServer()
			rec := postRegistration(t, srv, body)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
			}
			if got := decodeRegistrationBody(t, rec); got["error"] != "invalid_client_metadata" {
				t.Fatalf("expected invalid_client_metadata, got %v", got)
			}
		})
	}
}

func TestRegisterRejectsNonPost(t *testing.T) {
	t.Parallel()

	srv := newRegistrationTestServer()
	req := httptest.NewRequest(http.MethodGet, "/register", nil)
	rec := httptest.NewRecorder()
	srv.register(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for GET, got %d", rec.Code)
	}
}

func TestDiscoveryAdvertisesRegistrationEndpoint(t *testing.T) {
	t.Parallel()

	srv := newRegistrationTestServer()

	for path, handler := range map[string]http.HandlerFunc{
		"/.well-known/openid-configuration":       srv.openidConfiguration,
		"/.well-known/oauth-authorization-server": srv.oauthAuthorizationServer,
	} {
		rec := httptest.NewRecorder()
		handler(rec, httptest.NewRequest(http.MethodGet, path, nil))

		if rec.Code != http.StatusOK {
			t.Fatalf("%s: expected 200, got %d", path, rec.Code)
		}

		metadata := decodeRegistrationBody(t, rec)
		if metadata["registration_endpoint"] != "https://idp.example.com/register" {
			t.Fatalf("%s: unexpected registration_endpoint %v", path, metadata["registration_endpoint"])
		}
	}
}

func TestRegisteredClientViewsHideSecretAndSortNewestFirst(t *testing.T) {
	t.Parallel()

	srv := newRegistrationTestServer()
	first := postRegistration(t, srv, `{"client_name": "First", "redirect_uris": ["https://a.example.com/cb"]}`)
	second := postRegistration(t, srv, `{"client_name": "Second", "redirect_uris": ["https://b.example.com/cb"], "token_endpoint_auth_method": "none"}`)

	if first.Code != http.StatusCreated || second.Code != http.StatusCreated {
		t.Fatalf("expected both registrations to succeed")
	}

	views := srv.registeredClientViewsLocked()
	if len(views) != 2 {
		t.Fatalf("expected 2 client views, got %d", len(views))
	}
	for _, view := range views {
		if view.CreatedAt == "" {
			t.Fatalf("expected a formatted registration timestamp for %q", view.ClientID)
		}
		switch view.ClientName {
		case "First":
			if !view.Confidential {
				t.Fatalf("expected First to be confidential")
			}
		case "Second":
			if view.Confidential {
				t.Fatalf("expected Second to be public")
			}
		default:
			t.Fatalf("unexpected client name %q", view.ClientName)
		}
	}

	rendered, err := json.Marshal(views)
	if err != nil {
		t.Fatalf("marshal views: %v", err)
	}
	secret := srv.clients[decodeRegistrationBody(t, first)["client_id"].(string)].ClientSecret
	if secret == "" {
		t.Fatalf("expected the confidential client to have a secret")
	}
	if strings.Contains(string(rendered), secret) {
		t.Fatalf("client secret must not be exposed in dashboard views")
	}
}

func TestRegisteredClientViewsSortNewestFirst(t *testing.T) {
	t.Parallel()

	srv := newRegistrationTestServer()
	base := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	srv.clients["old"] = registeredClient{ClientID: "old", ClientName: "Old", CreatedAt: base}
	srv.clients["new"] = registeredClient{ClientID: "new", ClientName: "New", CreatedAt: base.Add(time.Hour)}

	views := srv.registeredClientViewsLocked()
	if len(views) != 2 || views[0].ClientID != "new" || views[1].ClientID != "old" {
		t.Fatalf("expected newest client first, got %v", views)
	}
}

func TestIndexRendersRegisteredClients(t *testing.T) {
	t.Parallel()

	templatesDir := filepath.Join("kodata", "templates")
	templates, err := loadTemplates(templatesDir)
	if err != nil {
		t.Fatalf("load templates: %v", err)
	}

	srv := newRegistrationTestServer()
	srv.templates = templates
	srv.templatesDir = templatesDir

	if rec := postRegistration(t, srv, `{"client_name": "Dashboard RP", "redirect_uris": ["https://rp.example.com/cb"]}`); rec.Code != http.StatusCreated {
		t.Fatalf("expected registration to succeed, got %d: %s", rec.Code, rec.Body.String())
	}

	rec := httptest.NewRecorder()
	srv.index(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	page := rec.Body.String()
	if !strings.Contains(page, "Registered Clients") {
		t.Fatalf("expected a registered clients section on the dashboard")
	}
	if !strings.Contains(page, "Dashboard RP") {
		t.Fatalf("expected the registered client name on the dashboard")
	}
	for clientID := range srv.clients {
		if !strings.Contains(page, clientID) {
			t.Fatalf("expected client_id %q on the dashboard", clientID)
		}
		if secret := srv.clients[clientID].ClientSecret; strings.Contains(page, secret) {
			t.Fatalf("client secret must not be rendered on the dashboard")
		}
	}
}

func TestDeleteAllClients(t *testing.T) {
	t.Parallel()

	srv := newRegistrationTestServer()
	postRegistration(t, srv, `{"redirect_uris": ["https://rp.example.com/callback"]}`)
	postRegistration(t, srv, `{"redirect_uris": ["https://other.example.com/callback"]}`)
	if len(srv.clients) != 2 {
		t.Fatalf("expected 2 registered clients, got %d", len(srv.clients))
	}

	req := httptest.NewRequest(http.MethodPost, "/clients/delete-all", nil)
	rec := httptest.NewRecorder()
	srv.deleteAllClients(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != srv.externalURL {
		t.Fatalf("expected redirect to %q, got %q", srv.externalURL, got)
	}
	if len(srv.clients) != 0 {
		t.Fatalf("expected no registered clients, got %d", len(srv.clients))
	}
}

func TestDeleteAllClientsRejectsGET(t *testing.T) {
	t.Parallel()

	srv := newRegistrationTestServer()
	req := httptest.NewRequest(http.MethodGet, "/clients/delete-all", nil)
	rec := httptest.NewRecorder()
	srv.deleteAllClients(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}
