<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

use BadMethodCallException;
use DateInterval;
use DateTimeImmutable;
use DateTimeInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\SimpleCache\CacheInterface;

/**
 * @covers \Firehed\WebAuthn\CacheChallengeManager
 */
class CacheChallengeManagerTest extends TestCase
{
    use ChallengeManagerTestTrait;

    protected function getChallengeManager(): ChallengeManagerInterface
    {
        $cache = new class implements CacheInterface
        {
            /**
             * @var array{mixed, ?DateTimeInterface}[]
             */
            private array $values = [];

            public function get(string $key, mixed $default = null): mixed
            {
                if (!$this->has($key)) {
                    return $default;
                }
                [$value, $exp] = $this->values[$key];
                if ($exp !== null && $exp < new DateTimeImmutable()) {
                    return $default;
                }

                return $value;
            }

            public function set(string $key, mixed $value, null|int|\DateInterval $ttl = null): bool
            {
                if (is_int($ttl)) {
                    $itvl = new DateInterval('PT' . $ttl . 'S');
                    $exp = (new DateTimeImmutable())->add($itvl);
                } elseif ($ttl instanceof DateInterval) {
                    $exp = (new DateTimeImmutable())->add($ttl);
                } else {
                    $exp = null;
                }
                $this->values[$key] = [$value, $exp];
                return true;
            }

            public function delete(string $key): bool
            {
                unset($this->values[$key]);
                return true;
            }

            public function clear(): bool
            {
                $this->values = [];
                return true;
            }

            public function getMultiple(iterable $keys, mixed $default = null): iterable
            {
                throw new BadMethodCallException();
            }

            /**
             * @param iterable<mixed> $values
             */
            public function setMultiple(iterable $values, null|int|\DateInterval $ttl = null): bool
            {
                throw new BadMethodCallException();
            }

            public function deleteMultiple(iterable $keys): bool
            {
                throw new BadMethodCallException();
            }

            public function has(string $key): bool
            {
                return array_key_exists($key, $this->values);
            }
        };
        return new CacheChallengeManager($cache);
    }
}
