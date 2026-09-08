<?php

declare(strict_types=1);

namespace XD\OIDCProvider\Repository;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use SilverStripe\Core\Injector\Injectable;
use XD\OIDCProvider\Entity\AccessTokenEntity;
use XD\OIDCProvider\Model\OAuthAccessToken;

class AccessTokenRepository implements AccessTokenRepositoryInterface
{
    use Injectable;

    public function getNewToken(
        ClientEntityInterface $clientEntity,
        array $scopes,
        string|null $userIdentifier = null
    ): AccessTokenEntityInterface {
        $token = new AccessTokenEntity();
        $token->setClient($clientEntity);
        foreach ($scopes as $scope) {
            /** @var ScopeEntityInterface $scope */
            $token->addScope($scope);
        }
        if ($userIdentifier !== null) {
            $token->setUserIdentifier($userIdentifier);
        }

        return $token;
    }

    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity): void
    {
        $record = OAuthAccessToken::create();
        $record->Identifier = $accessTokenEntity->getIdentifier();
        $record->ClientIdentifier = $accessTokenEntity->getClient()->getIdentifier();
        $record->MemberID = (int) $accessTokenEntity->getUserIdentifier();
        $record->Scopes = implode(' ', array_map(
            fn (ScopeEntityInterface $scope) => $scope->getIdentifier(),
            $accessTokenEntity->getScopes()
        ));
        $record->ExpiryUTC = $accessTokenEntity->getExpiryDateTime()->format('Y-m-d H:i:s');
        $record->Revoked = false;
        $record->write();
    }

    public function revokeAccessToken(string $tokenId): void
    {
        $record = OAuthAccessToken::get()->filter('Identifier', $tokenId)->first();
        if ($record) {
            $record->Revoked = true;
            $record->write();
        }
    }

    public function isAccessTokenRevoked(string $tokenId): bool
    {
        $record = OAuthAccessToken::get()->filter('Identifier', $tokenId)->first();
        return !$record || (bool) $record->Revoked;
    }
}
