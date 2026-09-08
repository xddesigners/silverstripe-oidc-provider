<?php

declare(strict_types=1);

namespace XD\OIDCProvider\Admin;

use SilverStripe\Admin\ModelAdmin;
use SilverStripe\Security\PermissionProvider;
use XD\OIDCProvider\Model\OAuthLoginLog;

/**
 * Read-only CMS view of the SSO login audit log. (Clients themselves are
 * developer-configured in .env / YAML, not here — this is only the log.)
 *
 * Visibility is governed by the module-defined permission `OIDC_VIEW_LOGIN_LOG`,
 * which an administrator can assign to any group under Security → Groups.
 * Full administrators (incl. the default admin) always have it. The required
 * code is a config property, so a project can point it at a different permission
 * via YAML if needed.
 */
class OAuthLoginLogAdmin extends ModelAdmin implements PermissionProvider
{
    private static string $url_segment = 'sso-logins';

    private static string $menu_title = 'SSO logins';

    private static string $menu_icon_class = 'font-icon-menu-security';

    private static array $managed_models = [
        OAuthLoginLog::class,
    ];

    private static $required_permission_codes = 'OIDC_VIEW_LOGIN_LOG';

    public function providePermissions(): array
    {
        return [
            'OIDC_VIEW_LOGIN_LOG' => [
                'name' => _t(__CLASS__ . '.PERMISSION_VIEW', 'View the SSO login log'),
                'category' => _t(__CLASS__ . '.PERMISSION_CATEGORY', 'OIDC provider'),
                'help' => _t(__CLASS__ . '.PERMISSION_HELP', 'Access the read-only SSO login audit log ("SSO logins").'),
                'sort' => 100,
            ],
        ];
    }
}
