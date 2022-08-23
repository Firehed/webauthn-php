<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

/**
 * @coversDefaultClass Firehed\WebAuthn\BinaryString
 * @covers ::<protected>
 * @covers ::<private>
 */
class BinaryStringTest extends \PHPUnit\Framework\TestCase
{
    public function testBinaryIsMasked(): void
    {
        $binaryString = new BinaryString(random_bytes(20));
        // Sanity-chceck that the random string actually contains binary. It's
        // possible (although _incredibly_ unlikely) that RNG would produce
        // pure ASCII.
        assert(ctype_print($binaryString->unwrap()) === false);

        // This test is... not the best.
        $outputFormatted = $binaryString->__debugInfo();
        foreach ($outputFormatted as $key => $value) {
            self::assertTrue(ctype_print($value), "$key contains non-printable characters");
        }
    }

    /**
     * @dataProvider equality
     */
    public function testEquals(BinaryString $lhs, BinaryString $rhs, bool $shouldMatch): void
    {
        self::assertSame($shouldMatch, $lhs->equals($rhs), 'lhs<->rhs');
        self::assertSame($shouldMatch, $rhs->equals($lhs), 'rhs<->lhs');
        self::assertTrue($lhs->equals($lhs), 'lhs should always equal itself');
        self::assertTrue($rhs->equals($rhs), 'rhs should always equal itself');
    }

    /**
     * @return array{BinaryString, BinaryString, bool}[]
     */
    public function equality(): array
    {
        return [
            [new BinaryString('abc123'), new BinaryString('abc123'), true],
            [new BinaryString('abc123'), new BinaryString('123abc'), false],
        ];
    }
}
