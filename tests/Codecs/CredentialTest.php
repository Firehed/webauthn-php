<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Codecs;

use Firehed\WebAuthn\{
    BinaryString,
    COSEKey,
    CredentialInterface,
    CredentialV1,
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

        $id = new BinaryString(random_bytes(10));
        $signCount = random_int(0, 20000);
        $credential = self::createMock(CredentialInterface::class);
        $credential->method('getId')->willReturn($id);
        $credential->method('getCoseCbor')->willReturn($coseKey->cbor);
        $credential->method('getSignCount')->willReturn($signCount);

        $codec = new Credential();

        $exported = $codec->encode($credential);

        $imported = $codec->decode($exported);
        // var_dump($exported, $imported);

        self::assertTrue(
            $id->equals($imported->getId()),
            'id was not retained',
        );
        self::assertSame(
            $coseKey->getPublicKey()->getPemFormatted(),
            $imported->getPublicKey()->getPemFormatted(),
            'public key was not retained',
        );
        self::assertSame(
            $signCount,
            $imported->getSignCount(),
            'signCount was not retained',
        );
    }

    /**
     * @dataProvider v1Credentials
     */
    public function testVersion1Import(string $encoded, BinaryString $id): void
    {
        $codec = new Credential();
        $credential = $codec->decode($encoded);

        self::assertTrue($credential->getId()->equals($id), 'Id changed');
        self::assertFalse($credential->isBackedUp(), 'V1 does not support backed up');
        self::assertFalse($credential->isBackupEligible(), 'V1 does not support backup eligibility');
        self::assertFalse($credential->isUvInitialized(), 'V1 does not support UV tracking');
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
                'IfPtrEJqgK1XvuaWVn8AAAAA',
                BinaryString::fromHex(
                    '08a9c38263974c246229cf0341b69d23263ce09f'
                ),
            ],
            'fidou2f' => [
                'AQBAdNgcVUDDGH2BZC8No6bNvCDgn+HW36AeRHtqbX4EICbjJO6XnpTQNz1G' .
                'VG/D+Fm9w5Sj5VtCFdtcJ7QRMS0UXQAAAE2lAQIDJiABIVggi2VjhUOZ3BdY' .
                'Jd9cJBHhhC+3yrxVjIlNHuak+SUYf0giWCAmEgP3PlrtjKb0XxB4Y3j6y6/Q' .
                'Bn6ljfpcewJaRdv4hQAAAAA=',
                BinaryString::fromHex(
                    '74d81c5540c3187d81642f0da3a6cdbc20e09fe1d6dfa01e447b6a6d' .
                    '7e042026e324ee979e94d0373d46546fc3f859bdc394a3e55b4215db' .
                    '5c27b411312d145d'
                ),
            ],
        ];
    }
}
