<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

interface ChallengeManagerInterface
{
    /**
     * Generates a new Challenge, stores it in the backing mechanism, and
     * returns it.
     *
     * @api
     */
    public function createChallenge(): ChallengeInterface;

    /**
     * Consumes the challenge associated with the ClientDataJSON value from the
     * underlying storage mechanism, and returns that challenge if found.
     *
     * Implementations MUST ensure that subsequent calls to this method with
     * the same value return `null`, regardless of whether the initial call
     * returned a value or null. Failure to do so will compromise the security
     * of the webauthn protocol.
     *
     * @internal
     */
    public function useFromClientDataJSON(string $base64url): ?ChallengeInterface;
}




class CacheChallengeManager
{
    public function __construct(
        private \Psr\SimpleCache\Cache $cache,
        private string $cacheKeyPrefix = 'webauthn-challenge-',
    ) {
    }

    public function createChallenge(): ChallengeInterface
    {
        $c = ExpiringChallenge::withLifetime(120);
        $cacheKey = sprintf(
            '%s%s',
            $this->cacheKeyPrefix,
            Codecs\Base64Url::encode($c->getBinary()->unwrap()),
        );
        $this->cache->set($cacheKey, $c, 120);
        return $c;
    }

    public function useFromClientDataJSON(string $base64url): ?ChallengeInterface
    {
        $key = sprintf(
            '%s%s',
            $this->cacheKeyPrefix,
            $base64url,
        );
        $active = $this->cache->get($key);
        if ($active === null) {
            return $active;
        }
        $this->cache->delete($key);
        return $active;
    }

}

class SessionChallengeManager
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

    /*
    public function getActiveChallenge(): ?ChallengeInterface
    {
        if (!array_key_exists(self::SESSION_KEY, $_SESSION)) {
            return null;
        }
        $challenge = $_SESSION[self::SESSION_KEY];
        unset($_SESSION[self::SESSION_KEY]);
        return $challenge;
    }
     */
}
