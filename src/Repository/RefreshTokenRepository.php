<?php

declare(strict_types=1);

namespace XD\OIDCProvider\Repository;

use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use SilverStripe\Core\Injector\Injectable;
use XD\OIDCProvider\Entity\RefreshTokenEntity;
use XD\OIDCProvider\Model\OAuthRefreshToken;

class RefreshTokenRepository implements RefreshTokenRepositoryInterface
{
    use Injectable;

    public function getNewRefreshToken(): ?RefreshTokenEntityInterface
    {
        return new RefreshTokenEntity();
    }

    public function persistNewRefreshToken(RefreshTokenEntityInterface $refreshTokenEntity): void
    {
        $record = OAuthRefreshToken::create();
        $record->Identifier = $refreshTokenEntity->getIdentifier();
        $record->AccessTokenIdentifier = $refreshTokenEntity->getAccessToken()->getIdentifier();
        $record->ExpiryUTC = $refreshTokenEntity->getExpiryDateTime()->format('Y-m-d H:i:s');
        $record->Revoked = false;
        $record->write();
    }

    public function revokeRefreshToken(string $tokenId): void
    {
        $record = OAuthRefreshToken::get()->filter('Identifier', $tokenId)->first();
        if ($record) {
            $record->Revoked = true;
            $record->write();
        }
    }

    public function isRefreshTokenRevoked(string $tokenId): bool
    {
        $record = OAuthRefreshToken::get()->filter('Identifier', $tokenId)->first();
        return !$record || (bool) $record->Revoked;
    }
}
