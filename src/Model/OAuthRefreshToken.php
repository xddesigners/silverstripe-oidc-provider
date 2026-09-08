<?php

declare(strict_types=1);

namespace XD\OIDCProvider\Model;

use SilverStripe\ORM\DataObject;
use SilverStripe\Security\Permission;

/**
 * Persisted refresh-token record (for revocation / rotation).
 */
class OAuthRefreshToken extends DataObject
{
    private static string $table_name = 'OIDC_OAuthRefreshToken';

    private static array $db = [
        'Identifier' => 'Varchar',
        'AccessTokenIdentifier' => 'Varchar',
        'ExpiryUTC' => 'Datetime',
        'Revoked' => 'Boolean',
    ];

    private static array $indexes = [
        'Identifier' => ['type' => 'unique', 'columns' => ['Identifier']],
    ];

    public function canView($member = null)
    {
        return Permission::check('ADMIN', 'any', $member);
    }

    public function canEdit($member = null)
    {
        return Permission::check('ADMIN', 'any', $member);
    }

    public function canCreate($member = null, $context = [])
    {
        return Permission::check('ADMIN', 'any', $member);
    }

    public function canDelete($member = null)
    {
        return Permission::check('ADMIN', 'any', $member);
    }
}
