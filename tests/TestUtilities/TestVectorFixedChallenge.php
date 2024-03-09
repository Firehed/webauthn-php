<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\TestUtilities;

use DateTimeImmutable;
use Exception;
use Firehed\WebAuthn\{
    BinaryString,
    ChallengeInterface,
};

/**
 * Like TestVectorChallengeLoader, this would be quite dangerous to use unless
 * challenges are coming from a known source. DO NOT USE THIS as an example
 * implementation.
 */
class TestVectorFixedChallenge implements ChallengeInterface
{
    public function __construct(private string $b64u)
    {
    }

    public function getExpiration(): ?DateTimeImmutable
    {
        return null;
    }

    public function getBinary(): BinaryString
    {
        return BinaryString::fromBase64Url($this->b64u);
    }

    public function getBase64(): string
    {
        throw new Exception('Not for use during testing');
    }

    public function getBase64Url(): string
    {
        throw new Exception('Not for use during testing');
    }
}
