<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

/**
 * Performs general integration testing with known-good data covering various
 * formats, attestation requirements, etc.
 *
 * @covers \Firehed\WebAuthn\Attestations\Apple
 * @covers \Firehed\WebAuthn\Attestations\FidoU2F
 * @covers \Firehed\WebAuthn\Attestations\None
 * @covers \Firehed\WebAuthn\Attestations\Packed
 * @covers \Firehed\WebAuthn\AuthenticatorData
 *
 * TODO: merge EndToEndTest into here
 */
class IntegrationTest extends TestCase
{
    /**
     * @dataProvider vectors
     */
    public function testReg(string $dir): void
    {
        $metadata = self::read($dir, 'metadata');
        // Future: more flexibility
        // @phpstan-ignore-next-line
        $rp = new SingleOriginRelyingParty($metadata['origin']);

        $createReq = self::read($dir, 'reg-req');
        $challengeManager = new TestUtilities\TestVectorChallengeManager(
            $createReq['publicKey']['challenge'], // @phpstan-ignore-line
        );

        $jrp = new JsonResponseParser();

        $createData = self::read($dir, 'reg-res');
        $createResponse = $jrp->parseCreateResponse($createData);

        $cred = $createResponse->verify(
            $challengeManager,
            $rp,
        );

        // More assertions to come!
        self::assertSame($metadata['id'], $cred->getId()->toBase64Url(), 'Credential ID wrong');
    }

    /**
     * @return array<string, array{string}>
     */
    public static function vectors(): array
    {
        $dirs = glob('tests/integration/*');
        assert($dirs !== false);
        $out = [];
        foreach ($dirs as $dir) {
            $out[$dir] = [$dir];
        }
        return $out;
    }

    /**
     * @return mixed[]
     */
    private static function read(string $dir, string $file): array
    {
        $file = sprintf('%s/%s.json', $dir, $file);
        $data = file_get_contents($file);
        assert($data !== false);
        return (array) json_decode($data, true, flags: JSON_THROW_ON_ERROR);
    }
}
