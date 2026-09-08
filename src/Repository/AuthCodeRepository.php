<?php

declare(strict_types=1);

namespace XD\OIDCProvider\Repository;

use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use SilverStripe\Core\Injector\Injectable;
use XD\OIDCProvider\Entity\AuthCodeEntity;
use XD\OIDCProvider\Model\OAuthAuthCode;

class AuthCodeRepository implements AuthCodeRepositoryInterface
{
    use Injectable;

    public function getNewAuthCode(): AuthCodeEntityInterface
    {
        return new AuthCodeEntity();
    }

    public function persistNewAuthCode(AuthCodeEntityInterface $authCodeEntity): void
    {
        $record = OAuthAuthCode::create();
        $record->Code = $authCodeEntity->getIdentifier();
        $record->ClientIdentifier = $authCodeEntity->getClient()->getIdentifier();
        $record->MemberID = (int) $authCodeEntity->getUserIdentifier();
        $record->Scopes = implode(' ', array_map(
            fn (ScopeEntityInterface $scope) => $scope->getIdentifier(),
            $authCodeEntity->getScopes()
        ));
        $record->RedirectUri = (string) $authCodeEntity->getRedirectUri();
        $record->ExpiryUTC = $authCodeEntity->getExpiryDateTime()->format('Y-m-d H:i:s');
        $record->Revoked = false;
        $record->write();
    }

    public function revokeAuthCode(string $codeId): void
    {
        $record = OAuthAuthCode::get()->filter('Code', $codeId)->first();
        if ($record) {
            $record->Revoked = true;
            $record->write();
        }
    }

    public function isAuthCodeRevoked(string $codeId): bool
    {
        $record = OAuthAuthCode::get()->filter('Code', $codeId)->first();
        return !$record || (bool) $record->Revoked;
    }
}
