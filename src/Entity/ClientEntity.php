<?php

declare(strict_types=1);

namespace XD\OIDCProvider\Entity;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\Traits\ClientTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;

class ClientEntity implements ClientEntityInterface
{
    use EntityTrait;
    use ClientTrait;

    public function setName(string $name): void
    {
        $this->name = $name;
    }

    /** @param string|string[] $uri */
    public function setRedirectUri(string|array $uri): void
    {
        $this->redirectUri = $uri;
    }

    public function setIsConfidential(bool $isConfidential): void
    {
        $this->isConfidential = $isConfidential;
    }
}
