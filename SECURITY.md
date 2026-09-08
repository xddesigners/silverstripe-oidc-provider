# Security model — silverstripe-oidc-provider

This module makes the site an Identity Provider: it issues tokens that grant access to external
Service Providers. Treat it as security-sensitive. This documents what is enforced and what still
needs attention.

## Enforced (phase 1)

- **Confidential clients only.** Client secrets live in `.env` (never in code or DB) and are compared
  in constant time (`hash_equals`). Empty/missing secret ⇒ rejected.
- **Exact redirect-URI allowlisting.** Redirect URIs are matched exactly by `league/oauth2-server`
  (no wildcards, no substring/prefix matching) ⇒ no open-redirect / token exfiltration to attacker URIs.
- **Signing/encryption keys from the environment.** RSA private key via `OIDC_PRIVATE_KEY_PATH`
  (outside the webroot, recommend `600`) or `OIDC_PRIVATE_KEY`; auth-code encryption key via
  `OIDC_ENCRYPTION_KEY`.
- **Short-lived, one-time authorization codes.** Encrypted by league, 10-minute TTL, single use
  (revoked on exchange). Persisted records store only identifiers (jti) — never a bearer secret.
- **PKCE required for public clients** (league default kept). Only confidential clients are issued here.
- **Safe login hand-off.** Unauthenticated requests go to the site login; `BackURL` is a local URL
  (Silverstripe anti-open-redirect), and on return `/authorize` re-validates the request through league,
  so an attacker-controlled `redirect_uri` cannot bypass the allowlist.
- **No information leak on errors.** Client-facing errors are the standard OAuth codes
  (`invalid_client`, …); unexpected errors return a generic `server_error` and are logged server-side.
- **Fail-closed scopes.** A client only ever receives scopes on its allowlist; an unconfigured
  allowlist falls back to the base OIDC identity scopes, never "everything requested".
- **Audit log.** Every `/oauth/authorize` outcome (success/error) is recorded in `OIDC_LoginLog`
  (member, client, scopes, result, IP, user-agent) — read-only in the CMS under "SSO logins".

## Hardening checklist for go-live

- [ ] Serve the provider only over HTTPS.
- [ ] Private key outside the webroot, `600`, owned by the web user. On the Parallels `/media/psf`
      dev mount chmod is not honoured — set `OIDCProviderService.key_permissions_check: false` there,
      but ensure real perms on production.
- [ ] Fresh `OIDC_ENCRYPTION_KEY` and key pair per environment (never reuse dev keys in production).
- [ ] Restrict each client's redirect URIs to the exact production Reply URL(s).

## Deferred (later phases)

- **Rate limiting / brute-force protection** on `/oauth/token` (secret guessing) and `/oauth/authorize`.
- **Consent screen** for any non-first-party client (current clients are auto-approved as trusted).
- **`nonce` echo** into the `id_token` — NOT yet implemented (the steverhoades id_token builder does
  not carry the request `nonce`); add it if a client requires nonce validation. (`/userinfo` already
  sends `Cache-Control: no-store`.)
- **Token revocation / RP-initiated logout**, and refresh-token rotation review.
- **Audit-log retention/purge** (the log stores IP + user-agent — apply a retention policy for GDPR).
- **Key rotation** via multiple JWKS keys (`kid`).
