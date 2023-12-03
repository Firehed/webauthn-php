<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

interface ChallengeInterface
{
    /**
     * @api
     *
     * While this is not deprecated, it's recommended to instead use
     * getBase64Url instead as it's more consistent with WebAuthn native
     * formats.
     */
    public function getBase64(): string;

    /**
     * @api
     */
    public function getBase64Url(): string;

    /**
     * @internal
     */
    public function getBinary(): BinaryString;
}
