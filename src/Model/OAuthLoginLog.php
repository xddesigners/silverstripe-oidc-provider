<?php

declare(strict_types=1);

namespace XD\OIDCProvider\Model;

use SilverStripe\ORM\DataObject;
use SilverStripe\Security\Member;
use SilverStripe\Security\Permission;

/**
 * Audit log of SSO authorization attempts (one row per /oauth/authorize outcome).
 * Read-only: written by the provider, viewed by admins — never edited by hand.
 */
class OAuthLoginLog extends DataObject
{
    private static string $table_name = 'OIDC_LoginLog';

    private static string $singular_name = 'SSO login';

    private static string $plural_name = 'SSO logins';

    private static array $db = [
        'ClientIdentifier' => 'Varchar(100)',
        'ClientName' => 'Varchar',
        'Scopes' => 'Varchar(512)',
        'Result' => "Enum('success,error','success')",
        'ErrorCode' => 'Varchar(100)',
        'IP' => 'Varchar(45)',
        'UserAgent' => 'Varchar(512)',
    ];

    private static array $has_one = [
        'Member' => Member::class,
    ];

    private static string $default_sort = 'Created DESC';

    /** Retention window in days for the prune task (0 = keep forever). */
    private static int $retention_days = 365;

    private static array $indexes = [
        'Created' => true,
        'ClientIdentifier' => true,
    ];

    private static array $summary_fields = [
        'Created.Nice' => 'When',
        'Member.Email' => 'Member',
        'ClientName' => 'Client',
        'Result' => 'Result',
        'IP' => 'IP',
    ];

    public function canView($member = null)
    {
        return Permission::check('OIDC_VIEW_LOGIN_LOG', 'any', $member);
    }

    // Read-only audit log: no manual create/edit/delete via the CMS.
    // (DataObject::write() from the provider bypasses canCreate, so logging still works.)
    public function canCreate($member = null, $context = [])
    {
        return false;
    }

    public function canEdit($member = null)
    {
        return false;
    }

    public function canDelete($member = null)
    {
        return false;
    }
}
