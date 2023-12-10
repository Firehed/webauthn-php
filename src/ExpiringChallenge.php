<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

use DateTimeInterface;
use DateInterval;
use DateTimeImmutable;
use InvalidArgumentException;

/**
 * This class provides a straightforward way to have short-lived challenges
 * without manual management. If the challenge is used after expiration, it
 * will throw an exception preventing additional progress.
 *
 * @api
 *
 * @phpstan-type SerializationFormat array{
 *   c: string,
 *   e: int,
 * }
 */
class ExpiringChallenge implements ChallengeInterface
{
    private ChallengeInterface $wrapped;
    private DateTimeInterface $expiration;

    /**
     * @internal
     */
    public function __construct(DateInterval $duration)
    {
        // TODO: If duration->invert && not in unit tests, throw?
        $this->wrapped = Challenge::random();
        $this->expiration = (new DateTimeImmutable())->add($duration);
    }

    /**
     * @param positive-int $seconds
     *
     * @api
     */
    public static function withLifetime(int $seconds): ChallengeInterface
    {
        if ($seconds <= 0) { // @phpstan-ignore-line Still need the runtime check here
            throw new InvalidArgumentException('Lifetime must be a postive integer');
        }
        $duration = sprintf('PT%dS', $seconds);
        return new ExpiringChallenge(new DateInterval($duration));
    }

    public function getBase64(): string
    {
        if ($this->isExpired()) {
            throw new Errors\ExpiredChallengeError();
        }
        return $this->wrapped->getBase64();
    }

    public function getBase64Url(): string
    {
        if ($this->isExpired()) {
            throw new Errors\ExpiredChallengeError();
        }
        return $this->wrapped->getBase64Url();
    }

    public function getBinary(): BinaryString
    {
        if ($this->isExpired()) {
            throw new Errors\ExpiredChallengeError();
        }
        return $this->wrapped->getBinary();
    }

    private function isExpired(): bool
    {
        $diff = $this->expiration->diff(new DateTimeImmutable());

        return $diff->invert === 0;
    }

    /**
     * @return SerializationFormat
     */
    public function __serialize(): array
    {
        return [
            'c' => $this->wrapped->getBase64(),
            'e' => $this->expiration->getTimestamp(),
        ];
    }

    /**
     * @param SerializationFormat $serialized
     */
    public function __unserialize(array $serialized): void
    {
        $this->wrapped = new Challenge(BinaryString::fromBase64($serialized['c']));
        $this->expiration = new DateTimeImmutable('@' . $serialized['e']);
    }
}
