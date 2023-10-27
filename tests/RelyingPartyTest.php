<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

/**
 * @coversDefaultClass Firehed\WebAuthn\RelyingParty
 * @covers ::<protected>
 * @covers ::<private>
 */
class RelyingPartyTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @dataProvider vectors
     */
    public function testIdAndOrigin(string $origin, string $id): void
    {
        $rp = new RelyingParty($origin);
        self::assertSame($origin, $rp->getOrigin(), 'Origin changed');
        self::assertSame($id, $rp->getId(), 'Id is incorrect');
    }

    /**
     * @dataProvider rpIdHashVectors
     */
    public function testRpIdHashMatching(string $origin, BinaryString $hash, bool $shouldMatch): void
    {
        $rp = new RelyingParty($origin);
        $ad = self::createMock(AuthenticatorData::class);
        $ad->method('getRpIdHash')->willReturn($hash);
        self::assertSame($shouldMatch, $rp->permitsRpIdHash($ad));
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
            ['http://localhost:8888', 'localhost'],
            ['https://webauthn.localhost:8888', 'webauthn.localhost'],
            ['https://www.example.com', 'www.example.com'],
            ['https://www.example.com:8443', 'www.example.com'],
        ];
    }
}
