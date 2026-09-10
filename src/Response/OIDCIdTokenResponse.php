<?php

declare(strict_types=1);

namespace XD\OIDCProvider\Response;

use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Builder;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use OpenIDConnectServer\ClaimExtractor;
use OpenIDConnectServer\IdTokenResponse;
use OpenIDConnectServer\Repositories\IdentityProviderInterface;
use XD\OIDCProvider\Support\NonceContext;

/**
 * Drop-in id_token response that sets `iss` to our canonical issuer.
 *
 * The upstream {@see IdTokenResponse} hardcodes `iss` to
 * `'https://' . $_SERVER['HTTP_HOST']`, which mismatches the discovery
 * document's `issuer` on non-https environments (and is fragile behind proxies).
 * We override the builder so the id_token `iss` always equals
 * {@see \XD\OIDCProvider\Service\OIDCProviderService::issuer()}.
 */
class OIDCIdTokenResponse extends IdTokenResponse
{
    private string $issuer;

    public function __construct(
        IdentityProviderInterface $identityProvider,
        ClaimExtractor $claimExtractor,
        string $issuer,
        ?string $keyIdentifier = null
    ) {
        parent::__construct($identityProvider, $claimExtractor, $keyIdentifier);
        $this->issuer = $issuer;
    }

    protected function getBuilder(AccessTokenEntityInterface $accessToken, UserEntityInterface $userEntity)
    {
        $builder = new Builder(new JoseEncoder(), ChainedFormatter::withUnixTimestampDates());

        $expiresAt = $accessToken->getExpiryDateTime();
        if ($expiresAt instanceof \DateTime) {
            $expiresAt = \DateTimeImmutable::createFromMutable($expiresAt);
        }

        $builder = $builder
            ->permittedFor($accessToken->getClient()->getIdentifier())
            ->issuedBy($this->issuer)
            ->issuedAt(new \DateTimeImmutable())
            ->expiresAt($expiresAt)
            ->relatedTo($userEntity->getIdentifier());

        // Echo the request nonce (OIDC): required by clients with RequireNonce.
        $nonce = NonceContext::forToken();
        if ($nonce !== null) {
            $builder = $builder->withClaim('nonce', $nonce);
        }

        return $builder;
    }
}
