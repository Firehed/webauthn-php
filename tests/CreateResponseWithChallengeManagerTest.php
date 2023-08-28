<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Firehed\WebAuthn\CreateResponse
 */
class CreateResponseWithChallengeManagerTest extends CreateResponseTest
{
    protected function getChallenge(): Challenge|ChallengeManagerInterface
    {
        $challenge = parent::getChallenge();
        assert($challenge instanceof Challenge);
        return new class ($challenge) implements ChallengeManagerInterface
        {
            private bool $accessed = false;
            public function __construct(private ChallengeInterface $challenge)
            {
            }

            public function createChallenge(): ChallengeInterface
            {
                return $this->challenge;
            }

            public function useFromClientDataJSON(string $base64Url): ?ChallengeInterface
            {
                if ($this->accessed) {
                    return null;
                }
                $this->accessed = true;
                return $this->challenge;
            }
        };
    }
}
