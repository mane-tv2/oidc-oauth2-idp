# idp-auth-server

Go implementation of the educational OIDC/OAuth2 Identity Provider from the
`oidc-oauth2-workshop` Python server, kept intentionally close to the original
flow and behavior.

## Run locally

From repo root:

```bash
make run
```

The server listens on `0.0.0.0:5001` by default.

## Useful URLs

- Index: `http://127.0.0.1:5001/`
- Discovery (OIDC): `http://127.0.0.1:5001/.well-known/openid-configuration`
- Discovery (OAuth 2.0, RFC 8414):
  `http://127.0.0.1:5001/.well-known/oauth-authorization-server`
- JWKS: `http://127.0.0.1:5001/.well-known/jwks.json`
- Dynamic client registration: `POST http://127.0.0.1:5001/register`
- Start auth flow (shows login page):

```text
http://127.0.0.1:5001/authorize?client_id=my-client&scope=openid+profile&redirect_uri=http://localhost:8080/callback&state=somestate
```

Login accepts any username and requires password `valid`.

## Dynamic client registration

The IdP implements [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591) dynamic
client registration so that clients — MCP clients in particular — can register
themselves. The `registration_endpoint` is advertised in both discovery
documents.

Registration is **open**: no initial access token is required. This matches the
rest of this IdP's intentionally permissive demo posture.

Register a public client (PKCE, no secret):

```bash
curl -sX POST http://127.0.0.1:5001/register \
  -H 'Content-Type: application/json' \
  -d '{
        "client_name": "My MCP Client",
        "redirect_uris": ["http://127.0.0.1:6274/oauth/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_method": "none"
      }'
```

Omit `token_endpoint_auth_method` (or set it to `client_secret_basic` /
`client_secret_post`) to get a confidential client; the generated
`client_secret` is returned once in the registration response and is never
displayed again.

Supported metadata and defaults:

| Field | Default | Accepted values |
| --- | --- | --- |
| `redirect_uris` | — (required for `authorization_code`) | absolute URIs without a fragment |
| `grant_types` | `["authorization_code"]` | `authorization_code`, `refresh_token` |
| `response_types` | `["code"]` | `code` |
| `scope` | `openid profile email` | any space-separated scope string |
| `token_endpoint_auth_method` | `client_secret_basic` | `client_secret_basic`, `client_secret_post`, `none` |
| `client_name` | empty | any string |

Invalid metadata is rejected with `400` and an `invalid_client_metadata` or
`invalid_redirect_uri` error, as specified in RFC 7591 section 3.2.2.

Registered clients are listed on the index page (name, `client_id`,
registration time, redirect URIs, grant types, scope, and whether the client is
confidential — never the secret).

Current limitations:

- Registrations are held in memory and lost when the process restarts.
- Client secrets are stored in plaintext in memory.
- Registration is **not yet enforced**: `/authorize` and `/token` still accept
  any `client_id` and `redirect_uri`, exactly as before.
- Client management (RFC 7592 read/update/delete of a registration) is not
  implemented.

## Environment variables

- `TEMPLATES_DIR` (default: `$KO_DATA_PATH/templates`)
  - Template/static directory used at runtime. Override this to select a bundled theme (for example `$KO_DATA_PATH/templates-ascii`) or point at a bind-mounted directory in containers.
- `KO_DATA_PATH` (default fallback for local runs: `idp-auth-server/kodata`)
  - Used to derive the default templates path when `TEMPLATES_DIR` is not set.
- `PORT` (default: `5001`)
  - HTTP listen port.
- `IDP_EXTERNAL_URL` (default: `http://127.0.0.1:5001`)
  - Public issuer URL used in discovery and token `iss` claims.
- `EXTRA_AUDIENCES` (default: empty)
  - Comma-separated list of additional audiences to include in access token `aud` claims.
  - Example: `EXTRA_AUDIENCES=https://api.example.com,https://inventory.example.com`
- `ACCESS_TOKEN_LIFETIME` (default: `1200`)
  - Access token lifetime in seconds.
- `REFRESH_TOKEN_LIFETIME` (default: `3600`)
  - Refresh token lifetime in seconds.
- `SUBJECT_TYPE` (default: `public`)
  - Subject identifier type: `public` or `pairwise`.
  - `public`: every RP receives the same `sub` for a given user.
  - `pairwise`: each RP receives a distinct, opaque `sub` derived via HMAC from the RP's sector identifier (host component of `redirect_uri`) and the user's internal subject. RPs cannot correlate users across sites.
- `PAIRWISE_SALT` (required when `SUBJECT_TYPE=pairwise`)
  - Hex-encoded HMAC-SHA256 secret, minimum 16 bytes (32 hex characters).
  - Example: `PAIRWISE_SALT=$(openssl rand -hex 32)`

## Development commands

From repo root:

- `make fmt` - format Go files
- `make lint` - run golangci-lint
- `make test` - run unit tests
- `make build` - build binary to `bin/idp-auth-server`
- `make container` - publish container image with `ko`
  - Defaults to `KO_DOCKER_REPO=ko.local`

## Templates in ko containers

The server loads templates from `TEMPLATES_DIR`.

- In ko-published images, templates are included from `idp-auth-server/kodata/templates` and available via `$KO_DATA_PATH/templates`.
- A second bundled ASCII theme is available at `idp-auth-server/kodata/templates-ascii` and can be selected with `TEMPLATES_DIR=$KO_DATA_PATH/templates-ascii`.
- To override templates at runtime, bind-mount a directory and set `TEMPLATES_DIR` to that mount path.

## Container publishing

Container publishing uses `ko` and `.ko.yaml`.

Default local publish:

```bash
make container
```

Publish to a remote registry:

```bash
KO_DOCKER_REPO=ghcr.io/<owner>/<repo> KO_TAGS=latest,<sha> make container
```
