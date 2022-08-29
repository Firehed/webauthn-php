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
