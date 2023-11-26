<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\TestUtilities;

use Exception;
use Firehed\WebAuthn\{
    BinaryString,
    ChallengeInterface,
    ChallengeManagerInterface,
};

class TestVectorChallengeManager implements ChallengeManagerInterface
{
    public function __construct(private string $b64u)
    {
    }

    public function createChallenge(): ChallengeInterface
    {
        throw new Exception('Not for use during testing');
    }

    public function useFromClientDataJSON(string $base64Url): ?ChallengeInterface
    {
        if ($this->b64u === $base64Url) {
            return new TestVectorFixedChallenge($base64Url);
        } else {
            return null;
        }
    }
}
