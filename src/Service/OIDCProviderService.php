<?php

declare(strict_types=1);

namespace XD\OIDCProvider\Service;

use DateInterval;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
use League\OAuth2\Server\ResourceServer;
use OpenIDConnectServer\ClaimExtractor;
use RuntimeException;
use SilverStripe\Control\Director;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Environment;
use SilverStripe\Core\Injector\Injectable;
use SilverStripe\Core\Injector\Injector;
use XD\OIDCProvider\Repository\AccessTokenRepository;
use XD\OIDCProvider\Repository\AuthCodeRepository;
use XD\OIDCProvider\Repository\ClientRepository;
use XD\OIDCProvider\Repository\IdentityRepository;
use XD\OIDCProvider\Repository\RefreshTokenRepository;
use XD\OIDCProvider\Repository\ScopeRepository;
use XD\OIDCProvider\Response\OIDCIdTokenResponse;

/**
 * Builds the configured league/oauth2-server servers (authorization + resource)
 * with the OpenID Connect id_token layer, wired to the Silverstripe-backed
 * repositories. Signing keys come from the environment:
 *
 *   OIDC_PRIVATE_KEY_PATH   absolute path to the RSA private key (chmod 600), or
 *   OIDC_PRIVATE_KEY        the PEM contents inline
 *   OIDC_ENCRYPTION_KEY     a high-entropy string, e.g. base64_encode(random_bytes(32))
 *
 * The public key (for /oauth/jwks and token validation) is derived from the
 * private key, so no separate public-key env var is needed.
 */
class OIDCProviderService
{
    use Injectable;
    use Configurable;

    /** ISO-8601 durations. */
    private static string $access_token_ttl = 'PT1H';

    private static string $auth_code_ttl = 'PT10M';

    private static string $refresh_token_ttl = 'P1M';

    /**
     * Verify the private-key file permissions (recommend 600). Set to false on
     * shared dev mounts (e.g. Parallels /media/psf) where chmod is not honoured
     * and the check would otherwise emit a spurious notice on every request.
     */
    private static bool $key_permissions_check = true;

    /** @var array<string,mixed>|null */
    private ?array $publicKeyDetailsCache = null;

    public function authorizationServer(): AuthorizationServer
    {
        $server = new AuthorizationServer(
            Injector::inst()->create(ClientRepository::class),
            Injector::inst()->create(AccessTokenRepository::class),
            Injector::inst()->create(ScopeRepository::class),
            $this->privateKey(),
            $this->encryptionKey(),
            $this->idTokenResponse()
        );

        $accessTokenTTL = new DateInterval((string) $this->config()->get('access_token_ttl'));

        $authCodeGrant = new AuthCodeGrant(
            Injector::inst()->create(AuthCodeRepository::class),
            Injector::inst()->create(RefreshTokenRepository::class),
            new DateInterval((string) $this->config()->get('auth_code_ttl'))
        );
        $authCodeGrant->setRefreshTokenTTL(new DateInterval((string) $this->config()->get('refresh_token_ttl')));
        $server->enableGrantType($authCodeGrant, $accessTokenTTL);

        $refreshGrant = new RefreshTokenGrant(Injector::inst()->create(RefreshTokenRepository::class));
        $refreshGrant->setRefreshTokenTTL(new DateInterval((string) $this->config()->get('refresh_token_ttl')));
        $server->enableGrantType($refreshGrant, $accessTokenTTL);

        return $server;
    }

    public function resourceServer(): ResourceServer
    {
        return new ResourceServer(
            Injector::inst()->create(AccessTokenRepository::class),
            $this->publicKeyPem()
        );
    }

    private function idTokenResponse(): OIDCIdTokenResponse
    {
        // Always our subclass: it sets `iss` to the canonical issuer
        // (Director::absoluteBaseURL — https on production, matching the discovery
        // document) AND echoes the request `nonce` into the id_token, which clients
        // with RequireNonce (e.g. Microsoft.IdentityModel — IDX21320) demand. The
        // upstream IdTokenResponse omits the nonce, so it must not be used.
        return new OIDCIdTokenResponse(
            Injector::inst()->create(IdentityRepository::class),
            new ClaimExtractor(),
            $this->issuer(),
            $this->keyId()
        );
    }

    /** The OIDC issuer identifier (this site's base URL, no trailing slash). */
    public function issuer(): string
    {
        return rtrim((string) Director::absoluteBaseURL(), '/');
    }

    /** Stable key id shared between the id_token header and the JWKS entry. */
    public function keyId(): string
    {
        return substr(hash('sha256', $this->publicKeyPem()), 0, 16);
    }

    public function publicKeyPem(): string
    {
        return (string) $this->publicKeyDetails()['key'];
    }

    /**
     * @return array<string,mixed> openssl_pkey_get_details() output for the key
     *         (includes 'key' = public PEM and 'rsa' => ['n','e'] binary).
     */
    public function publicKeyDetails(): array
    {
        if ($this->publicKeyDetailsCache !== null) {
            return $this->publicKeyDetailsCache;
        }

        $key = openssl_pkey_get_private($this->privateKeyContents());
        if ($key === false) {
            throw new RuntimeException('Unable to read the OIDC private key.');
        }

        $details = openssl_pkey_get_details($key);
        if ($details === false || !isset($details['key'])) {
            throw new RuntimeException('Unable to derive the OIDC public key from the private key.');
        }

        return $this->publicKeyDetailsCache = $details;
    }

    private function privateKey(): CryptKey
    {
        $path = Environment::getEnv('OIDC_PRIVATE_KEY_PATH');
        if ($path) {
            return new CryptKey('file://' . $path, null, (bool) $this->config()->get('key_permissions_check'));
        }

        $contents = Environment::getEnv('OIDC_PRIVATE_KEY');
        if ($contents) {
            return new CryptKey((string) $contents, null, false);
        }

        throw new RuntimeException(
            'OIDC signing key not configured: set OIDC_PRIVATE_KEY_PATH (preferred) or OIDC_PRIVATE_KEY.'
        );
    }

    private function privateKeyContents(): string
    {
        $path = Environment::getEnv('OIDC_PRIVATE_KEY_PATH');
        if ($path) {
            $contents = @file_get_contents((string) $path);
            if ($contents === false) {
                throw new RuntimeException('Unable to read OIDC_PRIVATE_KEY_PATH: ' . $path);
            }
            return $contents;
        }

        $contents = Environment::getEnv('OIDC_PRIVATE_KEY');
        if ($contents) {
            return (string) $contents;
        }

        throw new RuntimeException(
            'OIDC signing key not configured: set OIDC_PRIVATE_KEY_PATH (preferred) or OIDC_PRIVATE_KEY.'
        );
    }

    private function encryptionKey(): string
    {
        $key = Environment::getEnv('OIDC_ENCRYPTION_KEY');
        if (!$key) {
            throw new RuntimeException(
                'OIDC_ENCRYPTION_KEY not configured. Generate one, e.g. base64_encode(random_bytes(32)).'
            );
        }

        return (string) $key;
    }
}
