<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use InvalidArgumentException;

#[CoversClass(WildcardRelyingParty::class)]
class WildcardRelyingPartyTest extends TestCase
{
    #[DataProvider('originVectors')]
    public function testOriginMatching(string $rpId, string $origin, bool $shouldMatch): void
    {
        $rp = new WildcardRelyingParty($rpId);
        self::assertSame($shouldMatch, $rp->matchesOrigin($origin));
    }

    #[DataProvider('rpIdVectors')]
    public function testRpIdHashMatching(BinaryString $hash, bool $shouldMatch): void
    {
        $rp = new WildcardRelyingParty('example.com');
        $ad = self::createMock(AuthenticatorData::class);
        $ad->method('getRpIdHash')->willReturn($hash);
        self::assertSame($shouldMatch, $rp->permitsRpIdHash($ad));
    }

    /**
     * @return array{string, string, bool}[]
     */
    public static function originVectors(): array
    {
        return [
            'exact' => ['example.com', 'https://www.example.com', true],
            'subdomain 1' => ['example.com', 'https://app.example.com', true],
            'subdomain 2' => ['example.com', 'https://example.com', true],
            'nested sub' => ['example.com', 'https://super.admin.example.com', true],
            'wrong proto' => ['example.com', 'http://www.example.com', false],
            'other domain' => ['example.com', 'https://not-example.com', false],

            'localhost' => ['localhost', 'http://localhost', true],
            'localhost secure' => ['localhost', 'https://localhost', true],
            'localhost sub' => ['localhost', 'http://foo.localhost', true],
            'localhost two sub' => ['localhost', 'http://foo.bar.localhost', true],
            'localhost port' => ['localhost', 'http://localhost:3000', true],
            'ipv4 loopback' => ['127.0.0.1', 'http://127.0.0.1', true],
            // TODO: ipv6 loopback support
            // 'ipv6 loopback' => ['::1', 'http://[::1]', true],
            // Need to define behavior here
            // 'port change' => ['http://www.example.com:8443', false],
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
}
