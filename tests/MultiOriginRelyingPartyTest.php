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
    private RelyingPartyInterface $rp;

    public function setUp(): void
    {
        $this->rp = new MultiOriginRelyingParty(origins: [
            'https://www.example.com',
            'https://app.example.com',
            'https://admin.example.com',
            'https://example.com',
        ], rpId: 'example.com');
    }

    /**
     * @dataProvider originVectors
     */
    public function testOriginMatching(string $origin, bool $shouldMatch): void
    {
        self::assertSame($shouldMatch, $this->rp->matchesOrigin($origin));
    }

    /**
     * @dataProvider rpIdVectors
     */
    public function testRpIdHashMatching(BinaryString $hash, bool $shouldMatch): void
    {
        $ad = self::createMock(AuthenticatorData::class);
        $ad->method('getRpIdHash')->willReturn($hash);
        self::assertSame($shouldMatch, $this->rp->permitsRpIdHash($ad));
    }

    /**
     * @return array{string, bool}[]
     */
    public static function originVectors(): array
    {
        return [
            'in list' => ['https://www.example.com', true],
            'other in list' => ['https://app.example.com', true],
            'traversal in list' => ['https://example.com', true],
            'sub not in list' => ['https://test.example.com', false],
            'wrong proto' => ['http://www.example.com', false],
            'port change' => ['http://www.example.com:8443', false],
            'other domain' => ['https://not-example.com', false],
        ];
    }

    /**
     * @return array{BinaryString, bool}[]
     */
    public static function rpIdVectors(): array
    {
        $mbs = fn ($domainString) => new BinaryString(hash('sha256', $domainString, true));
        return [
            'domain match' => [$mbs('example.com'), true],
            'subdomain match' => [$mbs('www.example.com'), false],
            'domain mismatch' => [$mbs('not-example.com'), false],
        ];
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
}
