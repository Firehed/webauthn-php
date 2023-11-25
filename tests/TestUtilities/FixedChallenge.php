<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\TestUtilities;

use Exception;
use Firehed\WebAuthn\{
    BinaryString,
    ChallengeInterface,
};

class FixedChallenge implements ChallengeInterface
{
    public function __construct(private string $b64u)
    {
    }
    public function getBinary(): BinaryString
    {
        return BinaryString::fromBase64Url($this->b64u);
    }
    public function getBase64(): string
    {
        throw new Exception('Not for use during testing');
    }
}
