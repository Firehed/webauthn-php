<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

use Psr\SimpleCache\CacheInterface;

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
        $cacheKey = sprintf(
            '%s%s',
            $this->cacheKeyPrefix,
            Codecs\Base64Url::encode($c->getBinary()->unwrap()),
        );
        $this->cache->set($cacheKey, $c, 120);
        return $c;
    }

    public function useFromClientDataJSON(string $base64Url): ?ChallengeInterface
    {
        $key = sprintf(
            '%s%s',
            $this->cacheKeyPrefix,
            $base64Url,
        );
        // WARNING: race condition. Without at least a CAS guarantee, this
        // can't be avoided with SimpleCache.
        $active = $this->cache->get($key);
        if ($active === null) {
            return $active;
        }
        $this->cache->delete($key);
        return $active;
    }
}
