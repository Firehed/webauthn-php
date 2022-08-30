<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

/**
 * @covers Firehed\WebAuthn\COSEKey
 */
class COSEKeyTest extends \PHPUnit\Framework\TestCase
{
    public function testKeyParsing(): void
    {
        $cbor = BinaryString::fromHex(
            'a50102032620012158204c4c5bfc76bfc5cb1a51dc464c67f4cbecab779063c4' .
            '540993bcc397e472b84b2258202964b35782fe6bc89d7c310a623f77e94dc2ef' .
            'cdda936533cc93451ef6c39f71'
        );
        $coseKey = new COSEKey($cbor);
        $pk = $coseKey->getPublicKey();
        self::assertInstanceOf(PublicKey\EllipticCurve::class, $pk);
        self::assertTrue(
            BinaryString::fromHex('4c4c5bfc76bfc5cb1a51dc464c67f4cbecab779063c4540993bcc397e472b84b')
                ->equals($pk->getXCoordinate()),
            'X-coordinate wrong',
        );
        self::assertTrue(
            BinaryString::fromHex('2964b35782fe6bc89d7c310a623f77e94dc2efcdda936533cc93451ef6c39f71')
                ->equals($pk->getYCoordinate()),
            'Y-coordinate wrong',
        );
        // TODO: assert that it's a P256 key (see notes in EC class)
    }
}
