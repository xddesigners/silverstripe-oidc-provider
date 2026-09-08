# silverstripe-oidc-provider

Turns a Silverstripe site into an **OpenID Connect Provider / Identity Provider (IdP)**. The site
issues OAuth2/OIDC tokens for the already-logged-in `Member`, so external Service Providers can do
**SP-initiated SSO** against it.

It is login-agnostic: it only relies on `Security::getCurrentUser()`, so it works with the standard
login or with [`xddesigners/silverstripe-passwordless-login`](../silverstripe-passwordless-login).

> **Status: phase 2** — full OIDC: `/oauth/authorize`, `/oauth/token` (with `id_token`),
> `/oauth/userinfo`, `/.well-known/openid-configuration`, `/oauth/jwks`. Consent screen and
> rate-limiting are later phases. See `journal/PLAN-oidc-provider-module.md`.

## Requirements

- Silverstripe CMS 6, PHP 8.1+
- `league/oauth2-server ^9.3`, `steverhoades/oauth2-openid-connect-server ^3.0`, `guzzlehttp/psr7 ^2`

## Install

```bash
composer require xddesigners/silverstripe-oidc-provider
```

(While it is still developed in the webroot it is auto-discovered as a module; the third-party
dependencies must be present in the project's `vendor/` — add `league/oauth2-server` and
`steverhoades/oauth2-openid-connect-server` to the project `composer.json` and run composer in the VM.)

## Signing keys & config

The server signs tokens with an RSA key and encrypts auth codes with an encryption key. Neither lives
in the codebase — both come from the environment.

```bash
# RSA key pair (store OUTSIDE the webroot), private key readable only by the web user:
openssl genrsa -out /path/to/oidc/private.key 2048
openssl rsa -in /path/to/oidc/private.key -pubout -out /path/to/oidc/public.key
chmod 600 /path/to/oidc/private.key

# Encryption key:
php -r 'echo base64_encode(random_bytes(32)), PHP_EOL;'
```

Add to `.env`:

```
OIDC_PRIVATE_KEY_PATH="/path/to/oidc/private.key"
OIDC_ENCRYPTION_KEY="<the base64 string>"
```

Then flush: visit `http://<site>.test/dev/build?flush=all`.

Optional YAML (defaults shown):

```yaml
XD\OIDCProvider\Service\OIDCProviderService:
  access_token_ttl: 'PT1H'
  auth_code_ttl: 'PT10M'
  refresh_token_ttl: 'P1M'
```

## Register a client

Clients are configured by a **developer**, not in the CMS (an OAuth client is not something a content
editor should manage). Secrets live in `.env`.

**Single client (the common case) — `.env`:**

```
OIDC_CLIENT_ID="…"
OIDC_CLIENT_NAME="Example SP"
OIDC_CLIENT_SECRET="…"
OIDC_CLIENT_REDIRECT_URIS="https://…/reply"   # comma-separated; exact match, no wildcards
OIDC_CLIENT_SCOPES="openid profile email"
OIDC_CLIENT_GRANT_TYPES="authorization_code refresh_token"
```

Generate the id/secret with e.g. `php -r 'echo bin2hex(random_bytes(16));'` (id) and
`php -r 'echo bin2hex(random_bytes(32));'` (secret).

**Multiple OIDC couplings — YAML config**, one entry per client, each secret via `.env`:

```yaml
XD\OIDCProvider\Repository\ClientRepository:
  clients:
    example_sp:
      name: 'Example Service Provider'
      secret_env: 'OIDC_CLIENT_EXAMPLE_SECRET'
      redirect_uris: ['https://sp.example.com/oidc/callback']
      scopes: [openid, profile, email]
      grant_types: [authorization_code, refresh_token]
```

The `.env` single client and the YAML clients are merged, so you can use either or both.

## Endpoints

| Endpoint | Status |
|---|---|
| `GET /oauth/authorize` | ✅ |
| `POST /oauth/token` | ✅ (returns `id_token`) |
| `GET /oauth/userinfo` | ✅ (Bearer) |
| `GET /oauth/jwks` | ✅ |
| `GET /.well-known/openid-configuration` | ✅ |

Give the Service Provider the **Discovery URL** `https://<site>/.well-known/openid-configuration`
plus the `client_id` + `client_secret`; it can auto-configure the rest.

## Mapping to a Service Provider's OIDC config

- The Service Provider needs a **Client ID**, **Secret** and (optionally) the **Discovery URL**
  (`/.well-known/openid-configuration`).
- The Service Provider's **Reply URL** → the client's Redirect URI (allowlist).
- Required claims `email`, `given_name`, `family_name` map from `Member.Email/FirstName/Surname`.
  Optional `companyname`, `department`, `jobtitle` can be added per project with a Member extension
  implementing `updateOIDCClaims(array &$claims)`.

## Security

- Confidential clients only; secrets live in `.env` (never committed) and are compared in constant time (`hash_equals`).
- Redirect URIs are matched exactly (no wildcard/substring matching).
- PKCE is required for public clients (we only issue confidential clients here, which authenticate
  with their secret at the token endpoint).
- Auth codes / access tokens / refresh tokens are persisted by identifier for revocation; no bearer
  secret is stored server-side.
- Serve everything over HTTPS. Keep `OIDC_PRIVATE_KEY_PATH` outside the webroot with `600` perms.
