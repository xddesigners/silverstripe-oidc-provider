<?php

declare(strict_types=1);

namespace XD\OIDCProvider\Repository;

use OpenIDConnectServer\Repositories\IdentityProviderInterface;
use SilverStripe\Core\Injector\Injectable;
use SilverStripe\Security\Member;
use XD\OIDCProvider\Entity\UserEntity;

/**
 * Resolves a Member (by id = OIDC `sub`) into a user entity carrying OIDC claims.
 * Used by the id_token builder and the userinfo endpoint.
 *
 * Projects add extra claims (companyname, department, jobtitle, …) with a Member
 * extension implementing `updateOIDCClaims(array &$claims)`.
 */
class IdentityRepository implements IdentityProviderInterface
{
    use Injectable;

    /**
     * @param string|int $identifier
     * @return UserEntity|null
     */
    public function getUserEntityByIdentifier($identifier)
    {
        $member = Member::get()->byID((int) $identifier);
        if (!$member) {
            return null;
        }

        $claims = [
            'name' => trim(((string) $member->FirstName) . ' ' . ((string) $member->Surname)),
            'given_name' => (string) $member->FirstName,
            'family_name' => (string) $member->Surname,
            'email' => (string) $member->Email,
            'email_verified' => true,
        ];

        // Project hook: add/override claims (e.g. companyname/department/jobtitle).
        $member->extend('updateOIDCClaims', $claims);

        return new UserEntity((string) $member->ID, $claims);
    }
}
