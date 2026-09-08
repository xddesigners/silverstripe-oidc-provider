<?php

declare(strict_types=1);

namespace XD\OIDCProvider\Extension;

use SilverStripe\Core\Extension;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\GridField\GridField;
use SilverStripe\Forms\GridField\GridFieldConfig_RecordViewer;
use SilverStripe\Forms\GridField\GridFieldDataColumns;
use SilverStripe\Security\Permission;
use XD\OIDCProvider\Model\OAuthLoginLog;

/**
 * Adds a read-only "SSO logins" tab to the Member edit form showing that
 * member's SSO authorization history. Gated on the same OIDC_VIEW_LOGIN_LOG
 * permission as the global "SSO logins" section.
 *
 * @extends Extension<\SilverStripe\Security\Member>
 */
class MemberOIDCLogExtension extends Extension
{
    public function updateCMSFields(FieldList $fields): void
    {
        $member = $this->getOwner();
        if (!$member->exists() || !Permission::check('OIDC_VIEW_LOGIN_LOG')) {
            return;
        }

        $logs = OAuthLoginLog::get()->filter('MemberID', $member->ID);

        $config = GridFieldConfig_RecordViewer::create();
        $config->getComponentByType(GridFieldDataColumns::class)?->setDisplayFields([
            'Created.Nice' => 'When',
            'ClientName' => 'Client',
            'Result' => 'Result',
            'IP' => 'IP',
            'Scopes' => 'Scopes',
        ]);

        $fields->findOrMakeTab('Root.SSOLogins', _t(__CLASS__ . '.TAB', 'SSO logins'));
        $fields->addFieldToTab(
            'Root.SSOLogins',
            GridField::create('OIDCLoginLogs', 'SSO logins', $logs, $config)
        );
    }
}
