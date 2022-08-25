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
    /**
     * Internal offset pointer for read operations
     */
    private int $offset = 0;

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

    /**
     * Read the next $length bytes and advance the internal pointer by same.
     */
    public function read(int $length): string
    {
        $bytes = substr($this->wrapped, $this->offset, $length);
        $this->offset += $length;
        return $bytes;
    }

    /**
     * Read one byte and intreprets it as a big-endian Uint8. Advances pointer.
     */
    public function readUint8(): int
    {
        $byte = $this->read(1);
        // This could also use unpack(C)
        return ord($byte);
    }

    /**
     * Read two bytes and interprets them as a big-endian Uint16. Advances pointer.
     */
    public function readUint16(): int
    {
        $bytes = $this->read(2);
        return unpack('n', $bytes)[1];
    }

    /**
     * Read four bytes and interprets them as a big-endian Uint32. Advances pointer.
     */
    public function readUint32(): int
    {
        $bytes = $this->read(4);
        return unpack('N', $bytes)[1];
    }

    /**
     * Returns all of the remaining data after the offset. Does NOT advance the
     * offset.
     */
    public function getRemaining(): string
    {
        return substr($this->wrapped, $this->offset);
    }

    public function unwrap(): string
    {
        return $this->wrapped;
    }
}
