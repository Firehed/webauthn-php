<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

interface ResponseParserInterface
{
    /**
     * @param mixed[] $data
     */
    public function parseCreateResponse(array $data): Responses\AttestationInterface;

    /**
     * @param mixed[] $data
     */
    public function parseGetResponse(array $data): Responses\AssertionInterface;
}
