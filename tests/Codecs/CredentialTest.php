<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Codecs;

use Firehed\WebAuthn\{
    BinaryString,
    COSEKey,
    CredentialInterface,
    Credential as CredentialObj,
};

/**
 * @covers Firehed\WebAuthn\Codecs\Credential
 */
class CredentialTest extends \PHPUnit\Framework\TestCase
{
    public function testRoundtrip(): void
    {
        $cborHex = 'a50102032620012158204e9270bfb3a8cc360898793848bfe85451817' .
            'daaccc539e258a027c1118d81a22258201b9404e4ec6e7b303373c3f4b8fad46' .
            '4f255005a94e9b6f1a5b919654d7bb90e';
        $cbor = hex2bin($cborHex);
        assert($cbor !== false);
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

        self::assertTrue(
            $credential->getId()->equals($imported->getId()),
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

    /**
     * @dataProvider v1Credentials
     */
    public function testVersion1Import(string $encoded): void
    {
        $codec = new Credential();
        $credential = $codec->decode($encoded);

        self::assertInstanceOf(CredentialInterface::class, $credential);
    }

    /**
     * @return array{string}[]
     */
    public function v1Credentials(): array
    {
        return [
            'touchid/none' => [
                'AQAUCKnDgmOXTCRiKc8DQbadIyY84J8AAABNpQECAyYgASFYIL3IKTT4Q7Rw' .
                'jTpHJh23kPBaigTuTaeyq6zVE+INdRd1IlggT0NUfhOqpdq4LPEfITTPNO6e' .
                'IfPtrEJqgK1XvuaWVn8AAAAA'
            ],
            'fidou2f' => [
                'AQBAdNgcVUDDGH2BZC8No6bNvCDgn+HW36AeRHtqbX4EICbjJO6XnpTQNz1G' .
                'VG/D+Fm9w5Sj5VtCFdtcJ7QRMS0UXQAAAE2lAQIDJiABIVggi2VjhUOZ3BdY' .
                'Jd9cJBHhhC+3yrxVjIlNHuak+SUYf0giWCAmEgP3PlrtjKb0XxB4Y3j6y6/Q' .
                'Bn6ljfpcewJaRdv4hQAAAAA='
            ],
        ];
    }
}
