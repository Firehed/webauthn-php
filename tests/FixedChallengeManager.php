<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

class FixedChallengeManager implements ChallengeManagerInterface
{
    private ?ChallengeInterface $challenge;
    public function __construct(ChallengeInterface $challenge)
    {
        $this->challenge = $challenge;
    }
    public function createChallenge(): ChallengeInterface
    {
        assert($this->challenge !== null);
        return $this->challenge;
    }
    public function useFromClientDataJSON(string $base64Url): ?ChallengeInterface
    {
        $challenge = $this->challenge;
        // "consume" it after the first use
        $this->challenge = null;
        return $challenge;
    }
}
