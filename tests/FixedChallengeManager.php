<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

use BadMethodCallException;

class FixedChallengeManager implements ChallengeManagerInterface
{
    /** @var array<string, boolean> */
    private array $seen = [];

    public function __construct(private ChallengeInterface $challenge)
    {
    }

    public function createChallenge(): ChallengeInterface
    {
        throw new BadMethodCallException('Should not be used during testing');
    }

    public function useFromClientDataJSON(string $base64Url): ?ChallengeInterface
    {
        if (array_key_exists($base64Url, $this->seen)) {
            return null;
        }
        $this->seen[$base64Url] = true;
        return $this->challenge;
    }
}
