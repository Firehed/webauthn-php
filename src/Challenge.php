<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

/**
 * The Challenge object has limited public-facing API:
 * - Create a challenge through the `::random()` method
 * - (Un)Serialization through passing it to \serialize and \unserialize
 */
class Challenge
{
    /**
     * @internal
     */
    public function __construct(
        private BinaryString $wrapped,
    ) {
    }

    /**
     * @api
     */
    public static function random(): Challenge
    {
        return new Challenge(new BinaryString(random_bytes(32)));
    }

    /**
     * Caution: this returns raw binary
     * TODO: adjust name/interface?
     */
    public function getChallenge(): string
    {
        return $this->wrapped->unwrap();
    }

    /**
     * @return array{b64: string}
     */
    public function __serialize(): array
    {
        return ['b64' => base64_encode($this->wrapped->unwrap())];
    }

    /**
     * @param array{b64: string} $serialized
     */
    public function __unserialize(array $serialized): void
    {
        $bin = base64_decode($serialized['b64'], true);
        assert($bin !== false);
        $this->wrapped = new BinaryString($bin);
    }
}
