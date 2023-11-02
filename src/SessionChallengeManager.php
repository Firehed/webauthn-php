<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

use BadMethodCallException;

use function array_key_exists;
use function session_status;

use const PHP_SESSION_ACTIVE;

class SessionChallengeManager implements ChallengeManagerInterface
{
    private const SESSION_KEY = 'passkey_challenge';

    public function __construct()
    {
        // Do this later?
        if (session_status() !== PHP_SESSION_ACTIVE) {
            throw new BadMethodCallException('No active session. Call session_start() before using this.');
        }
    }

    public function createChallenge(): ChallengeInterface
    {
        $c = ExpiringChallenge::withLifetime(120);
        $_SESSION[self::SESSION_KEY] = $c;
        return $c;
    }

    public function useFromClientDataJSON(string $base64Url): ?ChallengeInterface
    {
        if (!array_key_exists(self::SESSION_KEY, $_SESSION)) {
            return null;
        }
        $challenge = $_SESSION[self::SESSION_KEY];
        unset($_SESSION[self::SESSION_KEY]);
        // Validate that the stored challenge matches the CDJ value?
        return $challenge;
    }
}
