<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

class RelyingParty
{
    public function __construct(
        private string $origin,
    ) {
    }

    public function getOrigin(): string
    {
        return $this->origin;
    }

    // TODO: getIds(): string[] <- you can walk up to the regsirable domain
    public function getId(): string
    {
        return parse_url($this->origin, PHP_URL_HOST);
    }
}
