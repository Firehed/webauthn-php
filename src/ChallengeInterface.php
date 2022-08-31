<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

interface ChallengeInterface
{
    public function getBase64(): string;

    /**
     * @internal
     */
    public function getBinary(): BinaryString;
}
