<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

/**
 * @internal
 */
class BinaryString
{
    public function __construct(
        private string $wrapped,
    ) {
    }

    /**
     * Turns a list of 8-bit integers into a BinaryString
     *
     * @param int[] $bytes
     */
    public static function fromBytes(array $bytes): BinaryString
    {
        return new BinaryString(implode('', array_map('chr', $bytes)));
    }

    public function equals(BinaryString $other): bool
    {
        return $this->wrapped === $other->wrapped;
    }

    public function __debugInfo()
    {
        return [
            'wrapped' => '0x' .  bin2hex($this->wrapped),
        ];
    }

    public function unwrap(): string
    {
        return $this->wrapped;
    }
}
