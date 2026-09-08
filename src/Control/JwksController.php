<?php

declare(strict_types=1);

namespace XD\OIDCProvider\Control;

use SilverStripe\Control\Controller;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use XD\OIDCProvider\Service\OIDCProviderService;

/**
 * JSON Web Key Set (/oauth/jwks) — publishes the RSA public key so clients can
 * verify id_token / access-token signatures. The `kid` matches the id_token header.
 */
class JwksController extends Controller
{
    use OAuthControllerTrait;

    private static array $allowed_actions = [
        'index',
    ];

    public function index(HTTPRequest $request): HTTPResponse
    {
        $service = OIDCProviderService::create();
        $details = $service->publicKeyDetails();
        $rsa = $details['rsa'] ?? null;

        if (!is_array($rsa) || !isset($rsa['n'], $rsa['e'])) {
            return $this->jsonResponse(['keys' => []]);
        }

        return $this->jsonResponse([
            'keys' => [
                [
                    'kty' => 'RSA',
                    'use' => 'sig',
                    'alg' => 'RS256',
                    'kid' => $service->keyId(),
                    'n' => $this->base64Url((string) $rsa['n']),
                    'e' => $this->base64Url((string) $rsa['e']),
                ],
            ],
        ]);
    }

    private function base64Url(string $binary): string
    {
        return rtrim(strtr(base64_encode($binary), '+/', '-_'), '=');
    }
}
