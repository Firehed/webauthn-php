<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

use Psr\SimpleCache\CacheInterface;
use RuntimeException;
use UnexpectedValueException;

use function assert;
use function bin2hex;
use function hash_equals;
use function is_string;
use function random_bytes;
use function sprintf;

class CacheChallengeManager implements ChallengeManagerInterface
{
    public function __construct(
        private CacheInterface $cache,
        private string $cacheKeyPrefix = 'webauthn-challenge-',
    ) {
    }

    public function createChallenge(): ChallengeInterface
    {
        $c = ExpiringChallenge::withLifetime(120);
        // The cache key is designed to mirror the comparison value used in
        // the `verify()` methods and `useFromClientDataJSON()` below.
        $key = $this->getKey(Codecs\Base64Url::encode($c->getBinary()->unwrap()));
        $this->cache->set($key, $c, 120);
        return $c;
    }

    public function useFromClientDataJSON(string $base64Url): ?ChallengeInterface
    {
        $key = $this->getKey($base64Url);

        // PSR-16 (through the shared definition in PSR-6) designates that
        // cache item deletion "MUST NOT be considered an error condition if the
        // specified key does not exist". Consequently, there's no way within
        // that interface to know if deletion was a no-op or actually removed
        // an item.
        //
        // Since this is used to managed cryptographic nonces and a race
        // condition could be exploited, this implementation does some
        // additional work (at the expense of some extra round-trips) to block
        // race conditions.
        //
        // First, generate a random value to store in the cache before doing
        // anything else. This value will be checked later.

        $raceConditionBlocker = bin2hex(random_bytes(10));
        $raceConditionBlockerKey = $key . '-rcb';
        $this->cache->set($raceConditionBlockerKey, $raceConditionBlocker, 120);

        // Retrieve the original value from the cache that would have been
        // stored during createChallenge().
        $challenge = $this->cache->get($key);

        // Remove it from the cache, as it is one-time-use. Always do this,
        // even if $challege above is null or invalid: this reduces the
        // possibility of other timing attacks.
        $deleteResult = $this->cache->delete($key);

        // Finally, read out the value stored above. If a race condition
        // occurred and another process or request overwrote the value with
        // a different random value, this will be different from the generated
        // value above. Look for this and throw an exception if detected.
        $raceConditionCheck = $this->cache->get($raceConditionBlockerKey, '');
        assert(is_string($raceConditionCheck));
        if (!hash_equals($raceConditionBlocker, $raceConditionCheck)) {
            throw new RuntimeException('Another process or request has used this challenge.');
        }

        // If unable to delete the challenge, abort. This is additional
        // insurance to block challenge reuse.
        if ($deleteResult === false) {
            throw new RuntimeException('Could not remove challenge from pool');
        }

        if ($challenge instanceof ChallengeInterface) {
            // Found, happy path
            return $challenge;
        } elseif ($challenge === null) {
            // Not found, either expired or potentially malicious.
            return null;
        }
        // Something interfered with the cache contents.
        throw new UnexpectedValueException('Non-challenge found in cache');
    }

    private function getKey(string $base64Url): string
    {
        return sprintf(
            '%s%s',
            $this->cacheKeyPrefix,
            $base64Url,
        );
    }
}
