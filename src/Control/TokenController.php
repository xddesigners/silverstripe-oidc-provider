<?php

declare(strict_types=1);

namespace XD\OIDCProvider\Control;

use GuzzleHttp\Psr7\Response as Psr7Response;
use GuzzleHttp\Psr7\ServerRequest;
use League\OAuth2\Server\Exception\OAuthServerException;
use SilverStripe\Control\Controller;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use XD\OIDCProvider\Service\OIDCProviderService;

/**
 * OAuth2/OIDC token endpoint (/oauth/token). Exchanges an authorization code
 * (or refresh token) for an access token + id_token. Confidential clients
 * authenticate with their secret here.
 */
class TokenController extends Controller
{
    use OAuthControllerTrait;

    private static array $allowed_actions = [
        'index',
    ];

    public function index(HTTPRequest $request): HTTPResponse
    {
        $server = OIDCProviderService::create()->authorizationServer();
        $psrRequest = ServerRequest::fromGlobals();

        try {
            return $this->toHTTPResponse(
                $server->respondToAccessTokenRequest($psrRequest, new Psr7Response())
            );
        } catch (OAuthServerException $exception) {
            return $this->toHTTPResponse($exception->generateHttpResponse(new Psr7Response()));
        } catch (\Throwable $exception) {
            return $this->serverErrorResponse($exception, 'token');
        }
    }
}
