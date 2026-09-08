<?php

declare(strict_types=1);

namespace XD\OIDCProvider\Control;

use GuzzleHttp\Psr7\Response as Psr7Response;
use GuzzleHttp\Psr7\ServerRequest;
use League\OAuth2\Server\Exception\OAuthServerException;
use OpenIDConnectServer\ClaimExtractor;
use SilverStripe\Control\Controller;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Core\Injector\Injector;
use XD\OIDCProvider\Repository\IdentityRepository;
use XD\OIDCProvider\Service\OIDCProviderService;

/**
 * OIDC userinfo endpoint (/oauth/userinfo). Validates the Bearer access token
 * and returns the claims permitted by its granted scopes.
 */
class UserInfoController extends Controller
{
    use OAuthControllerTrait;

    private static array $allowed_actions = [
        'index',
    ];

    public function index(HTTPRequest $request): HTTPResponse
    {
        $service = OIDCProviderService::create();
        $psrRequest = ServerRequest::fromGlobals();

        try {
            $validated = $service->resourceServer()->validateAuthenticatedRequest($psrRequest);
            $userId = (string) $validated->getAttribute('oauth_user_id');
            $scopeIds = (array) $validated->getAttribute('oauth_scopes');

            $user = Injector::inst()->create(IdentityRepository::class)->getUserEntityByIdentifier($userId);
            if (!$user) {
                throw OAuthServerException::accessDenied('Unknown user');
            }

            $claims = (new ClaimExtractor())->extract($scopeIds, $user->getClaims());
            $claims['sub'] = $userId;

            return $this->jsonResponse($claims, 200, true);
        } catch (OAuthServerException $exception) {
            return $this->toHTTPResponse($exception->generateHttpResponse(new Psr7Response()));
        } catch (\Throwable $exception) {
            return $this->serverErrorResponse($exception, 'userinfo');
        }
    }
}
