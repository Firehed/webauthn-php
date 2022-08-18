<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Codecs;

use Firehed\WebAuthn\{
    BinaryString,
    COSEKey,
    Credential as CredentialObj,
};

/**
 * @coversDefaultClass Firehed\WebAuthn\Codecs\Credential
 * @covers ::<protected>
 * @covers ::<private>
 */
class CredentialTest extends \PHPUnit\Framework\TestCase
{
    public function testRoundtrip(): void
    {
            // new COSEKey([
            //     1 => 2,
            //     3 => -7,
            //     -1 => 1,
            //     -2 => random_bytes(32),
            //     -3 => random_bytes(32),
            // ]),
        $cborHex = 'a50102032620012158204e9270bfb3a8cc360898793848bfe85451817daaccc539e258a027c1118d81a22258201b9404e4ec6e7b303373c3f4b8fad464f255005a94e9b6f1a5b919654d7bb90e';
        $cbor = hex2bin($cborHex);
        $coseKey = new COSEKey(new BinaryString($cbor));
        $credential = new CredentialObj(
            new BinaryString(random_bytes(10)),
            $coseKey,
            15,
        );

        $codec = new Credential();

        $exported = $codec->encode($credential);

        $imported = $codec->decode($exported);
        // var_dump($exported, $imported);

        self::assertSame(
            $credential->getSafeId(),
            $imported->getSafeId(),
            'id was not retained',
        );
        self::assertSame(
            $credential->getPublicKey()->getPemFormatted(),
            $imported->getPublicKey()->getPemFormatted(),
            'public key was not retained',
        );
        self::assertSame(
            $credential->getSignCount(),
            $imported->getSignCount(),
            'signCount was not retained',
        );
    }

    public function testVersion1Import(): void
    {
        self::markTestIncomplete('need vector');
    }
}
