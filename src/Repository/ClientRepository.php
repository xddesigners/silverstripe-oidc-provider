<?php

declare(strict_types=1);

namespace XD\OIDCProvider\Repository;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Environment;
use SilverStripe\Core\Injector\Injectable;
use XD\OIDCProvider\Entity\ClientEntity;

/**
 * Clients (relying parties) are configured by a developer, not in the CMS —
 * an OAuth client is not something a content editor should manage.
 *
 * Two sources, merged (env wins on id clash):
 *
 *  1. A single client straight from .env (the common case):
 *       OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_CLIENT_REDIRECT_URIS (comma-sep),
 *       OIDC_CLIENT_NAME, OIDC_CLIENT_SCOPES, OIDC_CLIENT_GRANT_TYPES (space-sep).
 *
 *  2. Any number of clients from YAML config (secret inline or via `secret_env`):
 *       XD\OIDCProvider\Repository\ClientRepository:
 *         clients:
 *           example_sp:
 *             name: 'Example Service Provider'
 *             secret_env: 'OIDC_CLIENT_EXAMPLE_SECRET'
 *             redirect_uris: ['https://.../reply']
 *             scopes: [openid, profile, email]
 *             grant_types: [authorization_code, refresh_token]
 *
 * Secrets live in .env, never in the codebase; they are compared in constant time.
 */
class ClientRepository implements ClientRepositoryInterface
{
    use Injectable;
    use Configurable;

    /** @var array<string,array> */
    private static array $clients = [];

    public function getClientEntity(string $clientIdentifier): ?ClientEntityInterface
    {
        $client = $this->clients()[$clientIdentifier] ?? null;
        if (!$client) {
            return null;
        }

        $entity = new ClientEntity();
        $entity->setIdentifier($clientIdentifier);
        $entity->setName($client['name']);
        $entity->setRedirectUri($client['redirect_uris']);
        // All configured clients are confidential (they hold a secret).
        $entity->setIsConfidential(true);

        return $entity;
    }

    public function validateClient(string $clientIdentifier, ?string $clientSecret, ?string $grantType): bool
    {
        $client = $this->clients()[$clientIdentifier] ?? null;
        if (!$client) {
            return false;
        }

        if ($client['secret'] === '' || !is_string($clientSecret) || !hash_equals($client['secret'], $clientSecret)) {
            return false;
        }

        if ($grantType !== null && !in_array($grantType, $client['grant_types'], true)) {
            return false;
        }

        return true;
    }

    /** @return string[] */
    public function allowedScopesFor(string $clientIdentifier): array
    {
        return $this->clients()[$clientIdentifier]['scopes'] ?? [];
    }

    /**
     * Resolve the merged client list, normalised to:
     *   [ id => ['name','secret','redirect_uris'[],'scopes'[],'grant_types'[]] ].
     *
     * @return array<string,array>
     */
    private function clients(): array
    {
        $clients = [];

        foreach ((array) $this->config()->get('clients') as $key => $def) {
            $id = (string) ($def['client_id'] ?? $key);
            $secret = $def['secret'] ?? null;
            if (!$secret && !empty($def['secret_env'])) {
                $secret = Environment::getEnv($def['secret_env']);
            }
            $clients[$id] = [
                'name' => (string) ($def['name'] ?? $id),
                'secret' => (string) ($secret ?: ''),
                'redirect_uris' => array_values((array) ($def['redirect_uris'] ?? [])),
                'scopes' => array_values((array) ($def['scopes'] ?? ['openid', 'profile', 'email'])),
                'grant_types' => array_values((array) ($def['grant_types'] ?? ['authorization_code', 'refresh_token'])),
            ];
        }

        $envId = Environment::getEnv('OIDC_CLIENT_ID');
        if ($envId) {
            $clients[(string) $envId] = [
                'name' => (string) (Environment::getEnv('OIDC_CLIENT_NAME') ?: 'OIDC client'),
                'secret' => (string) (Environment::getEnv('OIDC_CLIENT_SECRET') ?: ''),
                'redirect_uris' => $this->splitList((string) Environment::getEnv('OIDC_CLIENT_REDIRECT_URIS'), ','),
                'scopes' => $this->splitList((string) (Environment::getEnv('OIDC_CLIENT_SCOPES') ?: 'openid profile email'), ' '),
                'grant_types' => $this->splitList((string) (Environment::getEnv('OIDC_CLIENT_GRANT_TYPES') ?: 'authorization_code refresh_token'), ' '),
            ];
        }

        return $clients;
    }

    /** @return string[] */
    private function splitList(string $value, string $separator): array
    {
        $parts = $separator === ' '
            ? (preg_split('/\s+/', trim($value)) ?: [])
            : explode($separator, $value);

        return array_values(array_filter(array_map('trim', $parts), fn ($p) => $p !== ''));
    }
}
