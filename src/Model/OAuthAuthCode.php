<?php

declare(strict_types=1);

namespace XD\OIDCProvider\Model;

use SilverStripe\ORM\DataObject;
use SilverStripe\Security\Member;
use SilverStripe\Security\Permission;

/**
 * Persisted authorization code (for revocation / replay detection). Stores only
 * the code identifier and metadata — never a bearer secret.
 */
class OAuthAuthCode extends DataObject
{
    private static string $table_name = 'OIDC_OAuthAuthCode';

    private static array $db = [
        'Code' => 'Varchar',
        'ClientIdentifier' => 'Varchar(100)',
        'Scopes' => 'Varchar(512)',
        'RedirectUri' => 'Varchar(2048)',
        'Nonce' => 'Varchar(512)',
        'ExpiryUTC' => 'Datetime',
        'Revoked' => 'Boolean',
    ];

    private static array $has_one = [
        'Member' => Member::class,
    ];

    private static array $indexes = [
        'Code' => ['type' => 'unique', 'columns' => ['Code']],
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
