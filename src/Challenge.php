<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

// public, DTO?
// serializable?
class Challenge
{
    public function __construct(
        private BinaryString $wrapped,
    ) {
    }

    public static function random(int $length): Challenge
    {
        return new Challenge(new BinaryString(random_bytes($length)));
    }

    /**
     * Caution: this returns raw binary
     * TODO: adjust name/interface?
     */
    public function getChallenge(): string
    {
        return $this->wrapped->unwrap();
    }
}
