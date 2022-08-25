<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

/**
 * All read operations (any method starting with `read`) is a stateful
 * operation and moves an internal pointer. Read operations which return
 * integers will treat the underlying data as big-endian.
 *
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

    /** @return array{wrapped: string} */
    public function __debugInfo(): array
    {
        return [
            'wrapped' => '0x' .  bin2hex($this->wrapped),
        ];
    }

    // getLength(): int
    // getRemainingLength(): int = $length - $offset;

    private int $offset = 0;
    public function read(int $length): string
    {
        $bytes = substr($this->wrapped, $this->offset, $length);
        $this->offset += $length;
        return $bytes;
    }

    public function readUint8(): int
    {
        $byte = $this->read(1);
        return ord($byte);
    }

    public function readUint16(): int
    {
        $bytes = $this->read(2);
        return unpack('n', $bytes)[1];
    }
    public function readUint32(): int
    {
        $bytes = $this->read(4);
        return unpack('N', $bytes)[1];
    }
    public function getRemaining(): string
    {
        return substr($this->wrapped, $this->offset);
    }

    public function unwrap(): string
    {
        return $this->wrapped;
    }
}
