<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

// public, DTO?
// serializable?
class Challenge
{
    public function __construct(
        private string $wrapped,
    ) {
    }

    public static function random(int $length): Challenge
    {
        return new Challenge(random_bytes($length));
    }

    public function getChallenge(): string
    {
        return $this->wrapped;
    }
}
