<?php

declare(strict_types=1);

namespace XD\OIDCProvider\Entity;

use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\UserEntityInterface;
use OpenIDConnectServer\Entities\ClaimSetInterface;

/**
 * Wraps a Silverstripe Member as the OAuth2/OIDC "user". The identifier becomes
 * the OIDC `sub` claim, so it must be stable — we use the Member's database ID.
 *
 * Also carries the OIDC claim set ({@see ClaimSetInterface}); the ClaimExtractor
 * filters these by the granted scopes when building the id_token / userinfo.
 */
class UserEntity implements UserEntityInterface, ClaimSetInterface
{
    use EntityTrait;

    /** @var array<string,mixed> */
    private array $claims;

    /**
     * @param array<string,mixed> $claims
     */
    public function __construct(string $identifier, array $claims = [])
    {
        $this->setIdentifier($identifier);
        $this->claims = $claims;
    }

    /**
     * @param array<string,mixed> $claims
     */
    public function setClaims(array $claims): void
    {
        $this->claims = $claims;
    }

    /**
     * @return array<string,mixed>
     */
    public function getClaims(): array
    {
        return $this->claims;
    }
}
