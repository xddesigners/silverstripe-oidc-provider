<?php

declare(strict_types=1);

namespace XD\OIDCProvider\Control;

use GuzzleHttp\Psr7\Response as Psr7Response;
use GuzzleHttp\Psr7\ServerRequest;
use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Core\Injector\Injector;

/**
 * Shared PSR-7 ⇄ Silverstripe response helpers for the OAuth/OIDC endpoints.
 */
trait OAuthControllerTrait
{
    protected function toHTTPResponse(ResponseInterface $psrResponse): HTTPResponse
    {
        $response = HTTPResponse::create(
            (string) $psrResponse->getBody(),
            $psrResponse->getStatusCode()
        );

        foreach ($psrResponse->getHeaders() as $name => $values) {
            $response->addHeader($name, implode(', ', $values));
        }

        return $response;
    }

    protected function serverErrorResponse(\Throwable $exception, string $context): HTTPResponse
    {
        Injector::inst()->get(LoggerInterface::class)->error(
            'OIDC ' . $context . ' error: ' . $exception->getMessage(),
            ['exception' => $exception]
        );

        return $this->toHTTPResponse(
            OAuthServerException::serverError('Unexpected error')->generateHttpResponse(new Psr7Response())
        );
    }

    /**
     * @param array<string,mixed> $data
     */
    protected function jsonResponse(array $data, int $status = 200, bool $noStore = false): HTTPResponse
    {
        $response = HTTPResponse::create((string) json_encode($data, JSON_UNESCAPED_SLASHES), $status);
        $response->addHeader('Content-Type', 'application/json');
        if ($noStore) {
            $response->addHeader('Cache-Control', 'no-store');
            $response->addHeader('Pragma', 'no-cache');
        }

        return $response;
    }

    /**
     * Build the incoming PSR-7 request, robust against clients whose form body
     * PHP did not populate into $_POST.
     *
     * GuzzleHttp\Psr7\ServerRequest::fromGlobals() derives the parsed body from
     * $_POST, which PHP only fills for well-formed x-www-form-urlencoded /
     * multipart POSTs. Some clients (e.g. chunked transfer-encoding) leave $_POST
     * empty even though a form body was sent — which would make `grant_type`
     * appear missing at /oauth/token and yield "unsupported_grant_type". In that
     * case we re-parse the raw body so the OAuth parameters still arrive.
     */
    protected function psrServerRequest(): ServerRequestInterface
    {
        $request = ServerRequest::fromGlobals();

        $parsed = $request->getParsedBody();
        $isEmpty = $parsed === null || $parsed === [];

        if (
            $isEmpty
            && strtoupper($request->getMethod()) === 'POST'
            && stripos($request->getHeaderLine('Content-Type'), 'application/x-www-form-urlencoded') !== false
        ) {
            $raw = (string) $request->getBody();
            if ($raw !== '') {
                parse_str($raw, $fromRaw);
                if ($fromRaw !== []) {
                    $request = $request->withParsedBody($fromRaw);
                }
            }
        }

        return $request;
    }
}
