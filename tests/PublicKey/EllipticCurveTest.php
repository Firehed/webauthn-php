<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\PublicKey;

use Firehed\WebAuthn\BinaryString;

/**
 * @covers Firehed\WebAuthn\PublicKey\EllipticCurve
 */
class EllipticCurveTest extends \PHPUnit\Framework\TestCase
{
    public function testFormatHandling(): void
    {
        // Generated a keypair with openssl:
        //   openssl ecparam -name secp256r1 -genkey -noout -out pk.pem
        //
        // Get key info:
        //   openssl ec -in pk.pem -text -noout
        //
        // Manually copied the output in the `pub:` section, removing the
        // leading `04:` (which is a format indicator for uncompressed) and set
        // into $x and $y below
        //
        // Extracted public key:
        //    openssl ec -in pk.pem -pubout pub.pem
        // and copied into $opensslPubKey

        $x = BinaryString::fromHex('0f06777d44842cce4a2e7d00587b3fc892a7da7cf1704a8dd1ffb7e5334721a8');
        $y = BinaryString::fromHex('3f017188437532409d6bbc86b68d56214a720bf8c183f844c576f4e2003ba976');

        $pk = new EllipticCurve($x, $y);
        self::assertTrue($x->equals($pk->getXCoordinate()), 'X-coordinate changed');
        self::assertTrue($y->equals($pk->getYCoordinate()), 'Y-coordinate changed');

        $opensslPubKey = <<<PEM
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDwZ3fUSELM5KLn0AWHs/yJKn2nzx
        cEqN0f+35TNHIag/AXGIQ3UyQJ1rvIa2jVYhSnIL+MGD+ETFdvTiADupdg==
        -----END PUBLIC KEY-----
        PEM;

        self::assertSame($opensslPubKey, $pk->getPemFormatted(), 'pubkey format changed');
    }
}
