<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Codecs;

use Firehed\WebAuthn\{
    Attestations\AttestationObject,
    BinaryString,
    COSEKey,
    CredentialInterface,
    CredentialV1,
    CredentialV2,
    Enums,
};

/**
 * @covers Firehed\WebAuthn\Codecs\Credential
 */
class CredentialTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @dataProvider credentials
     */
    public function testRoundtrip(CredentialInterface $credential): void
    {
        $codec = new Credential();
        $exported = $codec->encode($credential);
        $imported = $codec->decode($exported);

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
        self::assertSame(
            $credential->isUvInitialized(),
            $imported->isUvInitialized(),
            'isUvInitialized was not retained',
        );
        self::assertSame(
            $credential->isBackupEligible(),
            $imported->isBackupEligible(),
            'signCount was not retained',
        );
        self::assertSame(
            $credential->isBackedUp(),
            $imported->isBackedUp(),
            'isBackedUp was not retained',
        );
        self::assertEqualsCanonicalizing(
            $credential->getTransports(),
            $imported->getTransports(),
            'transports were not retained',
        );
        self::assertEquals(
            $credential->getAttestationData(),
            $imported->getAttestationData(),
            'Attestation data was not retained',
        );
        self::assertSame(
            $credential->getPublicKey()->getPemFormatted(),
            $imported->getPublicKey()->getPemFormatted(),
            'public key changed',
        );

        $attestationStrippingCodec = new Credential(storeRegistrationData: false);
        $strippedEncoded = $attestationStrippingCodec->encode($credential);
        $stripped = $attestationStrippingCodec->decode($strippedEncoded);

        self::assertNull($stripped->getAttestationData(), 'Attestation should have been removed');
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

        $reencoded = $codec->encode($credential);
        self::assertSame($encoded, $reencoded, 'Should have reencoded to v1');
    }

    /**
     * @dataProvider v2Credentials
     */
    public function testVersion2Import(string $encoded): void
    {
        $codec = new Credential();
        $decoded = $codec->decode($encoded);
        self::assertInstanceOf(CredentialV2::class, $decoded);
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

    /**
     * @return array{string}[]
     */
    public static function v2Credentials(): array
    {
        return [
            'no att cert' => [
                'AgsACv69Y58M4y3CsWkAADEXAAAATaUBAgMmIAEhWCBOknC/s6jMNgiYeThI' .
                'v+hUUYF9qszFOeJYoCfBEY2BoiJYIBuUBOTsbnswM3PD9Lj61GTyVQBalOm2' .
                '8aW5GWVNe7kOMQ==',
            ],
            'saved att cert' => [
                'AhgACr/Sj9YstWchvM4AADBlAAAATaUBAgMmIAEhWCBOknC/s6jMNgiYeThI' .
                'v+hUUYF9qszFOeJYoCfBEY2BoiJYIBuUBOTsbnswM3PD9Lj61GTyVQBalOm2' .
                '8aW5GWVNe7kODAAAA20AAAB1o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjeDVj' .
                'gVkCMTCCAi0wggEXoAMCAQICBAW2BXkwCwYJKoZIhvcNAQELMC4xLDAqBgNV' .
                'BAMTI1l1YmljbyBVMkYgUm9vdCBDQSBTZXJpYWwgNDU3MjAwNjMxMCAXDTE0' .
                'MDgwMTAwMDAwMFoYDzIwNTAwOTA0MDAwMDAwWjAoMSYwJAYDVQQDDB1ZdWJp' .
                'Y28gVTJGIEVFIFNlcmlhbCA5NTgxNTAzMzBZMBMGByqGSM49AgEGCCqGSM49' .
                'AwEHA0IABP243rOh7XDrY2wGbrYAaZal+XD8tduI/DswXUHllm8MG1S4Uv7w' .
                'oJB+0X87/8KdTTIbnPioSizqoDjKvTXVmN6jJjAkMCIGCSsGAQQBgsQKAgQV' .
                'MS4zLjYuMS40LjEuNDE0ODIuMS4xMAsGCSqGSIb3DQEBCwOCAQEAftP7bMwl' .
                'IBP4LyGMKjfaYDHSDn8wgdr8rrEo/H+bIzkUv7ZNYTXxfOIh+nZPRT7xJzqM' .
                '6WWVZEK7Lx5HSD9zfcvJi1hTd/71CycOAon4hDbxrc9JsmIe5eMC31VbmrdC' .
                'cuBp+RgUmz3sTxIiixDA+I3javWKdLtEK4WuAFNkvaZwIFj8Hy2Hm1MBEepg' .
                '6Gxj8X+llEzIPwqiaYSLPuOIpsCeawWVP8u49H6Don4AcqY8Mq1khk6SbXES' .
                '+hmX94OWVvuzK+j3iJ0PAUVRmiev3Y5GsEykKQ2FQLY0uIYWHnWIyGKZ3N1k' .
                'NdFnijpvCnSCnE3T9ww1JNHd8W14rdIbZGNzaWdYSDBGAiEA6Q/IoHy9emgq' .
                'byDa/5id6H0/MJvAkT28HNb0iEO36MUCIQDD+UZZBz0PIZUrJ77OliPPmtFO' .
                'SOW/u1vzX7aYe4lcLWhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4/krrmi' .
                'hjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQHyt9XuGzGoH2Hhm' .
                'Gh/lNyFaCv+v9V79jigJZuZ5LtnWuOw9Ph+WfrA1HeHw33tqFbQ/5AYjo6E6' .
                'atlqFXZ6NRqlAQIDJiABIVggaORWdx8A3Tw55VDl5Hi3H+RC/TxUJvuyeFjT' .
                'FHz4zHwiWCC2nNEOYCncBKKLJpU536AHVsp4sHIJWtt8fAqF5ihlmHsiY2hh' .
                'bGxlbmdlIjoiNkVScmZFSVNYaXJYTm1iX1hMa0NlM2REdml0cEdkYVlvX3FY' .
                'N0J5YmFvQSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6Nzc3NyIsInR5' .
                'cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ=='
            ],
        ];
    }

    /**
     * @return array{CredentialInterface}[]
     */
    public static function credentials(): array
    {
        $cborHex = 'a50102032620012158204e9270bfb3a8cc360898793848bfe85451817' .
            'daaccc539e258a027c1118d81a22258201b9404e4ec6e7b303373c3f4b8fad46' .
            '4f255005a94e9b6f1a5b919654d7bb90e';
        $cbor = hex2bin($cborHex);
        assert($cbor !== false);
        $coseKey = new COSEKey(new BinaryString($cbor));

        $makeId = fn () => new BinaryString(random_bytes(10));

        $aod = BinaryString::fromBase64Url(
            'o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjeDVjgVkCMTCCAi0wggEXoAMCAQICBAW2' .
            'BXkwCwYJKoZIhvcNAQELMC4xLDAqBgNVBAMTI1l1YmljbyBVMkYgUm9vdCBDQSBT' .
            'ZXJpYWwgNDU3MjAwNjMxMCAXDTE0MDgwMTAwMDAwMFoYDzIwNTAwOTA0MDAwMDAw' .
            'WjAoMSYwJAYDVQQDDB1ZdWJpY28gVTJGIEVFIFNlcmlhbCA5NTgxNTAzMzBZMBMG' .
            'ByqGSM49AgEGCCqGSM49AwEHA0IABP243rOh7XDrY2wGbrYAaZal-XD8tduI_Dsw' .
            'XUHllm8MG1S4Uv7woJB-0X87_8KdTTIbnPioSizqoDjKvTXVmN6jJjAkMCIGCSsG' .
            'AQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS4xMAsGCSqGSIb3DQEBCwOCAQEA' .
            'ftP7bMwlIBP4LyGMKjfaYDHSDn8wgdr8rrEo_H-bIzkUv7ZNYTXxfOIh-nZPRT7x' .
            'JzqM6WWVZEK7Lx5HSD9zfcvJi1hTd_71CycOAon4hDbxrc9JsmIe5eMC31VbmrdC' .
            'cuBp-RgUmz3sTxIiixDA-I3javWKdLtEK4WuAFNkvaZwIFj8Hy2Hm1MBEepg6Gxj' .
            '8X-llEzIPwqiaYSLPuOIpsCeawWVP8u49H6Don4AcqY8Mq1khk6SbXES-hmX94OW' .
            'VvuzK-j3iJ0PAUVRmiev3Y5GsEykKQ2FQLY0uIYWHnWIyGKZ3N1kNdFnijpvCnSC' .
            'nE3T9ww1JNHd8W14rdIbZGNzaWdYSDBGAiEA6Q_IoHy9emgqbyDa_5id6H0_MJvA' .
            'kT28HNb0iEO36MUCIQDD-UZZBz0PIZUrJ77OliPPmtFOSOW_u1vzX7aYe4lcLWhh' .
            'dXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAAAAA' .
            'AAAAAAAAAAAAAAAAAAAAQHyt9XuGzGoH2HhmGh_lNyFaCv-v9V79jigJZuZ5LtnW' .
            'uOw9Ph-WfrA1HeHw33tqFbQ_5AYjo6E6atlqFXZ6NRqlAQIDJiABIVggaORWdx8A' .
            '3Tw55VDl5Hi3H-RC_TxUJvuyeFjTFHz4zHwiWCC2nNEOYCncBKKLJpU536AHVsp4' .
            'sHIJWtt8fAqF5ihlmA'
        );
        $ao = new AttestationObject($aod);

        $cdj = BinaryString::fromBase64Url(
            'eyJjaGFsbGVuZ2UiOiI2RVJyZkVJU1hpclhObWJfWExrQ2UzZER2aXRwR2RhWW9f' .
            'cVg3QnliYW9BIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo3Nzc3IiwidHlw' .
            'ZSI6IndlYmF1dGhuLmNyZWF0ZSJ9'
        );

        return [
            [new CredentialV2(
                id: $makeId(),
                type: Enums\PublicKeyCredentialType::PublicKey,
                coseKey: $coseKey,
                signCount: random_int(20, 20000),
                isBackupEligible: true,
                isBackedUp: false,
                isUvInitialized: true,
                transports: [
                    Enums\AuthenticatorTransport::Ble,
                    Enums\AuthenticatorTransport::Usb,
                    Enums\AuthenticatorTransport::SmartCard,
                ],
                attestation: null,
            )],
            [new CredentialV2(
                id: $makeId(),
                type: Enums\PublicKeyCredentialType::PublicKey,
                coseKey: $coseKey,
                signCount: random_int(20, 20000),
                isBackupEligible: false,
                isBackedUp: false,
                isUvInitialized: false,
                transports: [
                    Enums\AuthenticatorTransport::Nfc,
                    Enums\AuthenticatorTransport::Internal,
                ],
                attestation: [$ao, $cdj],
            )],
            [new CredentialV2(
                id: $makeId(),
                type: Enums\PublicKeyCredentialType::PublicKey,
                coseKey: $coseKey,
                signCount: random_int(20, 20000),
                isBackupEligible: true,
                isBackedUp: true,
                isUvInitialized: false,
                transports: [],
                attestation: [$ao, $cdj],
            )],
            // Ideally, this would have a ton of permutations of the various
            // flags. That's un unreasonable amount of test vectors to write.
            // For now, this aims to hit the likely issues: off-by-one errors,
            // especially those stemming from skip-bits
        ];
    }
}
