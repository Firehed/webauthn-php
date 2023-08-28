<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

class SessionChallengeManager implements ChallengeManagerInterface
{
    private const SESSION_KEY = 'passkey_challenge';

    public function __construct()
    {
        // do later?
        if (session_status() !== PHP_SESSION_ACTIVE) {
            throw new \BadMethodCallException('Call session_start()');
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
        // TODO: match url?
        if (!array_key_exists(self::SESSION_KEY, $_SESSION)) {
            return null;
        }
        $challenge = $_SESSION[self::SESSION_KEY];
        unset($_SESSION[self::SESSION_KEY]);
        return $challenge;
    }
}
