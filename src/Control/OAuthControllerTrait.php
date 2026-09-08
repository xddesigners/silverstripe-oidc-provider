<?php

declare(strict_types=1);

namespace XD\OIDCProvider\Control;

use GuzzleHttp\Psr7\Response as Psr7Response;
use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Http\Message\ResponseInterface;
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
}
