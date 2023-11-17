<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

use OutOfBoundsException;

/**
 * @covers Firehed\WebAuthn\BinaryString
 */
class BinaryStringTest extends \PHPUnit\Framework\TestCase
{
    private BinaryString $default;

    public function setUp(): void
    {
        $this->default = new BinaryString("\xDE\xAD\xBE\xEFplaintext");
    }

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

    public function testGetLength(): void
    {
        self::assertSame(13, $this->default->getLength());
        $_ = $this->default->read(2);
        self::assertSame(13, $this->default->getLength(), 'Length must not change after read');
    }

    public function testReadingExactIsOk(): void
    {
        $str = new BinaryString('abc123');
        self::assertSame('abc123', $str->read(6));
    }

    public function testReadingTooFarThrows(): void
    {
        $str = new BinaryString('abc123');
        $this->expectException(OutOfBoundsException::class);
        $str->read(20);
    }

    public function testReadUint8(): void
    {
        self::assertSame(0xDE, $this->default->readUint8());
        self::assertSame("\xAD\xBE\xEFplaintext", $this->default->getRemaining());
        self::assertSame(0xAD, $this->default->readUint8());
        self::assertSame("\xBE\xEFplaintext", $this->default->getRemaining());
        self::assertSame(0xBE, $this->default->readUint8());
        self::assertSame("\xEFplaintext", $this->default->getRemaining());
        self::assertSame(0xEF, $this->default->readUint8());
        self::assertSame('plaintext', $this->default->getRemaining());
    }

    public function testReadUint16(): void
    {
        self::assertSame(0xDEAD, $this->default->readUint16());
        self::assertSame("\xBE\xEFplaintext", $this->default->getRemaining());
        self::assertSame(0xBEEF, $this->default->readUint16());
        self::assertSame('plaintext', $this->default->getRemaining());
    }

    public function testReadUint32(): void
    {
        self::assertSame(0xDEADBEEF, $this->default->readUint32());
        self::assertSame('plaintext', $this->default->getRemaining());
    }

    public function testBase64UrlIdentity(): void
    {
        $data = random_bytes(64);
        $wrapped = new BinaryString($data);
        $b64u = $wrapped->toBase64Url();
        $decoded = BinaryString::fromBase64Url($b64u);
        self::assertSame($data, $decoded->unwrap());
    }

    public function testBase64UrlDecode(): void
    {
        $decoded = BinaryString::fromBase64Url('PDw_Pz8-Pg');
        self::assertSame('<<???>>', $decoded->unwrap());
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
