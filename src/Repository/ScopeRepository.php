<?php

declare(strict_types=1);

namespace XD\OIDCProvider\Repository;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Injector\Injectable;
use SilverStripe\Core\Injector\Injector;
use XD\OIDCProvider\Entity\ScopeEntity;

class ScopeRepository implements ScopeRepositoryInterface
{
    use Injectable;
    use Configurable;

    /**
     * Scopes this provider knows about. OIDC claim-bearing scopes (profile,
     * email) are honoured by the OIDC layer in a later phase.
     *
     * @var string[]
     */
    private static array $supported_scopes = ['openid', 'profile', 'email', 'offline_access'];

    public function getScopeEntityByIdentifier(string $identifier): ?ScopeEntityInterface
    {
        $supported = (array) $this->config()->get('supported_scopes');
        if (!in_array($identifier, $supported, true)) {
            return null;
        }

        $scope = new ScopeEntity();
        $scope->setIdentifier($identifier);

        return $scope;
    }

    public function finalizeScopes(
        array $scopes,
        string $grantType,
        ClientEntityInterface $clientEntity,
        string|null $userIdentifier = null,
        ?string $authCodeId = null
    ): array {
        // Never grant a scope the client is not registered for. Fail CLOSED: an
        // unconfigured allowlist falls back to the base OIDC identity scopes
        // rather than granting whatever the client happened to request.
        $allowed = Injector::inst()->get(ClientRepository::class)->allowedScopesFor($clientEntity->getIdentifier());
        if (!$allowed) {
            $allowed = ['openid', 'profile', 'email'];
        }

        return array_values(array_filter(
            $scopes,
            fn (ScopeEntityInterface $scope) => in_array($scope->getIdentifier(), $allowed, true)
        ));
    }
}
