<?php

declare(strict_types=1);

namespace XD\OIDCProvider\Control;

use SilverStripe\Control\Controller;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use XD\OIDCProvider\Service\OIDCProviderService;

/**
 * OIDC discovery document (/.well-known/openid-configuration). This is the
 * "Discovery URL" a Service Provider can be given so it auto-configures the endpoints.
 */
class DiscoveryController extends Controller
{
    use OAuthControllerTrait;

    private static array $allowed_actions = [
        'index',
    ];

    public function index(HTTPRequest $request): HTTPResponse
    {
        $issuer = OIDCProviderService::create()->issuer();

        return $this->jsonResponse([
            'issuer' => $issuer,
            'authorization_endpoint' => $issuer . '/oauth/authorize',
            'token_endpoint' => $issuer . '/oauth/token',
            'userinfo_endpoint' => $issuer . '/oauth/userinfo',
            'jwks_uri' => $issuer . '/oauth/jwks',
            'response_types_supported' => ['code'],
            'grant_types_supported' => ['authorization_code', 'refresh_token'],
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['RS256'],
            'scopes_supported' => ['openid', 'profile', 'email', 'offline_access'],
            'claims_supported' => ['sub', 'name', 'given_name', 'family_name', 'email', 'email_verified'],
            'token_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post'],
            'code_challenge_methods_supported' => ['S256'],
        ]);
    }
}
