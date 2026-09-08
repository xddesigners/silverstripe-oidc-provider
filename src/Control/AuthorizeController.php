<?php

declare(strict_types=1);

namespace XD\OIDCProvider\Control;

use GuzzleHttp\Psr7\Response as Psr7Response;
use GuzzleHttp\Psr7\ServerRequest;
use League\OAuth2\Server\Exception\OAuthServerException;
use SilverStripe\Control\Controller;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Security\Security;
use XD\OIDCProvider\Entity\UserEntity;
use XD\OIDCProvider\Model\OAuthLoginLog;
use XD\OIDCProvider\Service\OIDCProviderService;

/**
 * OAuth2/OIDC authorization endpoint (/oauth/authorize).
 *
 * SP-initiated flow: the Service Provider client redirects the browser here.
 * If the visitor already has a Silverstripe session the request is completed
 * silently (that is the "already logged in on the site → logged in on the Service
 * Provider" behaviour). Otherwise we hand off to the normal login (passwordless)
 * and return here via BackURL.
 */
class AuthorizeController extends Controller
{
    use OAuthControllerTrait;

    private static array $allowed_actions = [
        'index',
    ];

    /** Record each authorization outcome in OAuthLoginLog. */
    private static bool $enable_login_log = true;

    public function index(HTTPRequest $request): HTTPResponse
    {
        $server = OIDCProviderService::create()->authorizationServer();
        $psrRequest = ServerRequest::fromGlobals();

        try {
            $authRequest = $server->validateAuthorizationRequest($psrRequest);

            $member = Security::getCurrentUser();
            if (!$member) {
                $back = '/' . ltrim($request->getURL(true), '/');
                return $this->redirect(Security::login_url() . '?BackURL=' . urlencode($back));
            }

            $authRequest->setUser(new UserEntity((string) $member->ID));

            // Auto-approve: clients here are developer-configured and trusted.
            // An optional consent screen is a later phase.
            $authRequest->setAuthorizationApproved(true);

            $response = $this->toHTTPResponse(
                $server->completeAuthorizationRequest($authRequest, new Psr7Response())
            );

            $this->recordLogin(
                'success',
                $request,
                (int) $member->ID,
                $authRequest->getClient()->getIdentifier(),
                (string) $authRequest->getClient()->getName(),
                array_map(fn ($scope) => $scope->getIdentifier(), $authRequest->getScopes()),
                null
            );

            return $response;
        } catch (OAuthServerException $exception) {
            $params = $psrRequest->getQueryParams();
            $this->recordLogin(
                'error',
                $request,
                (int) (Security::getCurrentUser()?->ID ?? 0),
                (string) ($params['client_id'] ?? ''),
                '',
                [],
                $exception->getErrorType()
            );
            return $this->toHTTPResponse($exception->generateHttpResponse(new Psr7Response()));
        } catch (\Throwable $exception) {
            return $this->serverErrorResponse($exception, 'authorize');
        }
    }

    /**
     * @param string[] $scopes
     */
    private function recordLogin(
        string $result,
        HTTPRequest $request,
        int $memberId,
        string $clientId,
        string $clientName,
        array $scopes,
        ?string $errorCode
    ): void {
        if (!static::config()->get('enable_login_log')) {
            return;
        }

        try {
            $log = OAuthLoginLog::create();
            $log->Result = $result;
            $log->MemberID = $memberId;
            $log->ClientIdentifier = $clientId;
            $log->ClientName = $clientName;
            $log->Scopes = implode(' ', $scopes);
            $log->ErrorCode = (string) $errorCode;
            $log->IP = (string) $request->getIP();
            $log->UserAgent = substr((string) $request->getHeader('User-Agent'), 0, 512);
            $log->write();
        } catch (\Throwable $e) {
            // Logging must never break the authorization flow.
        }
    }
}
