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
    public function createChallenge(): ChallengeInterface
    {
        throw new Exception('Not for use during testing');
    }

    /**
     * This would be an EXTREMELY INSECURE implementation, as it would allow
     * clients to control the challenges and bypass server-side verification
     * that it was a legitimiately issued challenge.
     *
     * ABSOLUTELY DO NOT EVER DO THIS IN A REAL IMPLEMENTATION.
     */
    public function useFromClientDataJSON(string $base64Url): ChallengeInterface
    {
        return new TestVectorFixedChallenge($base64Url);
    }
}
