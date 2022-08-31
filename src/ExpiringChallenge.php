<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

use DateTimeInterface;
use DateInterval;
use DateTimeImmutable;

/**
 * This class provides a straightforward way to have short-lived challenges
 * without manual management. If the challenge is used after expiration, it
 * will throw an exception preventing additional progress.
 *
 * @api
 */
class ExpiringChallenge implements ChallengeInterface
{
    private ChallengeInterface $wrapped;
    private DateTimeInterface $expiration;

    public function __construct(DateInterval $duration)
    {
        // TODO: If duration->invert && not in unit tests, throw?
        $this->wrapped = Challenge::random();
        $this->expiration = (new DateTimeImmutable())->add($duration);
    }

    public function getBase64(): string
    {
        if ($this->isExpired()) {
            throw new Errors\ExpiredChallengeError();
        }
        return $this->wrapped->getBase64();
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
}
