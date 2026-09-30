<?php

declare(strict_types=1);

namespace XD\OIDCProvider\Support;

use OpenIDConnectServer\ClaimExtractor;
use OpenIDConnectServer\Entities\ClaimSetEntity;

/**
 * ClaimExtractor that permits extra, non-standard claims (e.g. companyname,
 * department, jobtitle) under the OIDC `profile` scope, so they survive the
 * scope-based extraction and reach the id_token / userinfo response.
 *
 * The upstream {@see ClaimExtractor} treats `profile` as a "protected" scope
 * that cannot be extended through addClaimSet() (it throws), so we rebuild the
 * profile claim set directly. The extra claim names are injected (configured on
 * {@see \XD\OIDCProvider\Service\OIDCProviderService}) to keep the module generic.
 */
class OIDCClaimExtractor extends ClaimExtractor
{
    /**
     * @param string[] $extraProfileClaims
     */
    public function __construct(array $extraProfileClaims = [])
    {
        parent::__construct();

        if ($extraProfileClaims === []) {
            return;
        }

        $profile = $this->getClaimSet('profile');
        $claims = $profile ? $profile->getClaims() : [];
        $claims = array_values(array_unique(array_merge($claims, $extraProfileClaims)));

        // `profile` is protected in the parent; replace its claim set directly
        // rather than via addClaimSet() (which throws for a protected scope).
        $this->claimSets['profile'] = new ClaimSetEntity('profile', $claims);
    }
}
