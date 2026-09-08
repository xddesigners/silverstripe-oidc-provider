<?php

declare(strict_types=1);

namespace XD\OIDCProvider\Model;

use SilverStripe\ORM\DataObject;
use SilverStripe\Security\Member;
use SilverStripe\Security\Permission;

/**
 * Persisted access-token record (for revocation lookups). Access tokens are
 * self-contained signed JWTs held by the client; here we store only the token
 * identifier (jti) and metadata, never the token itself.
 */
class OAuthAccessToken extends DataObject
{
    private static string $table_name = 'OIDC_OAuthAccessToken';

    private static array $db = [
        'Identifier' => 'Varchar',
        'ClientIdentifier' => 'Varchar(100)',
        'Scopes' => 'Varchar(512)',
        'ExpiryUTC' => 'Datetime',
        'Revoked' => 'Boolean',
    ];

    private static array $has_one = [
        'Member' => Member::class,
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
