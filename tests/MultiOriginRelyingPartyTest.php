<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

use InvalidArgumentException;

/**
 * @coversDefaultClass Firehed\WebAuthn\MultiOriginRelyingParty
 * @covers ::<protected>
 * @covers ::<private>
 */
class MultiOriginRelyingPartyTest extends \PHPUnit\Framework\TestCase
{
    public function testValidConstruct(): void
    {
        $rp = new MultiOriginRelyingParty(origins: [
            'https://www.example.com',
            'https://app.example.com',
            'https://admin.example.com',
            'https://example.com',
        ], rpId: 'example.com');
        self::assertInstanceOf(RelyingParty::class, $rp);
    }

    public function testInvalidConstruct(): void
    {
        self::expectException(InvalidArgumentException::class);
        new MultiOriginRelyingParty(origins: [
            'https://www.example.com',
            'https://app.example.com',
            'https://admin.example.com',
            'https://www.not-example.com',
        ], rpId: 'example.com');
    }

    /**
     * @dataProvider rpIdHashVectors
     */
    public function testRpIdHashMatching(string $origin, BinaryString $hash, bool $shouldMatch): void
    {
        $rp = new MultiOriginRelyingParty($origin);
        $ad = self::createMock(AuthenticatorData::class);
        $ad->method('getRpIdHash')->willReturn($hash);
        self::assertSame($shouldMatch, $rp->permitsRpIdHash($ad));
        self::assertTrue($rp->matchesOrigin($origin));
    }

    /**
     * @return array{string, BinaryString, bool}[]
     */
    public static function rpIdHashVectors(): array
    {
        $mbs = fn ($domainString) => new BinaryString(hash('sha256', $domainString, true));
        return [
            'localhost match' => ['http://localhost:3000', $mbs('localhost'), true],
            'domain match' => ['https://example.com', $mbs('example.com'), true],
            'subdomain match' => ['https://www.example.com', $mbs('www.example.com'), true],
            'domain mismatch' => ['https://example.com', $mbs('not-example.com'), false],
            'domain+sub mismatch' => ['https://www.example.com', $mbs('not-example.com'), false],
            // More to come as subdomain handling is expanded
            // This MAY change
            'subdomain traversal' => ['https://www.example.com', $mbs('example.com'), false],
        ];
    }

    /**
     * @return array{string, string}[]
     */
    public function vectors(): array
    {
        return [
            ['http://localhost:8888', 'http://localhost:8888', true],
            ['http://localhost:8888', 'http://localhost:8889', false],
            ['http://localhost:8888', 'http://localhost', false],
            ['https://www.example.com', 'https://www.example.com', true],
            ['https://www.example.com', 'https://sub.www.example.com', false],
            ['https://www.example.com', 'https://app.example.com', false],
            ['https://www.example.com', 'https://example.com', false],
            ['https://www.example.com', 'https://www.not-example.com', false],
            ['https://www.example.com:8443', 'https://www.example.com:8443', true],
            ['https://www.example.com:8443', 'https://www.example.com', false],
            ['https://www.example.com:8443', 'https://example.com:8443', false],
        ];
    }
}
