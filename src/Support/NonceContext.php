<?php

declare(strict_types=1);

namespace XD\OIDCProvider\Support;

/**
 * Request-scoped carrier for the OIDC `nonce`. PHP-FPM resets static state per
 * request, so these values never leak between requests.
 *
 *  - Authorize request: the `nonce` query param is captured ({@see setIncoming()})
 *    and persisted with the authorization code.
 *  - Token request: the auth code's nonce is looked up ({@see setForToken()}) and
 *    the id_token builder echoes it back as the `nonce` claim (required by clients
 *    that set RequireNonce, e.g. Microsoft.IdentityModel — IDX21320).
 */
final class NonceContext
{
    private static ?string $incoming = null;

    private static ?string $forToken = null;

    public static function setIncoming(?string $nonce): void
    {
        self::$incoming = ($nonce !== null && $nonce !== '') ? $nonce : null;
    }

    public static function incoming(): ?string
    {
        return self::$incoming;
    }

    public static function setForToken(?string $nonce): void
    {
        self::$forToken = ($nonce !== null && $nonce !== '') ? $nonce : null;
    }

    public static function forToken(): ?string
    {
        return self::$forToken;
    }
}
