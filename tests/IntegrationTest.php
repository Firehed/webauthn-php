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
 * @covers \Firehed\WebAuthn\PublicKey\EllipticCurve
 * @covers \Firehed\WebAuthn\PublicKey\RSA
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

        $jrp = new JsonResponseParser();

        $createData = self::read($dir, 'reg-res');
        $createResponse = $jrp->parseCreateResponse($createData);

        $cred = $createResponse->verify(
            self::getChallengeFromVector($dir, 'reg-req'),
            $rp,
            rejectUncertainTrustPaths: false,
        );

        // More assertions to come!
        self::assertSame($metadata['id'], $cred->getId()->toBase64Url(), 'Registration: Credential ID wrong');
    }

    /**
     * @dataProvider vectors
     */
    public function testAuth(string $dir): void
    {
        if (!file_exists($dir . '/auth-req.json')) {
            self::markTestIncomplete('No auth vector');
        }

        $metadata = self::read($dir, 'metadata');
        $rp = new SingleOriginRelyingParty($metadata['origin']); // @phpstan-ignore-line
        // Note: I wanted to @depend this, but it seems incompatible with
        // @dataProvider... so it's duplicated
        $jrp = new JsonResponseParser();

        $createResponse = $jrp->parseCreateResponse(self::read($dir, 'reg-res'));
        $cred = $createResponse->verify(
            self::getChallengeFromVector($dir, 'reg-req'),
            $rp,
            rejectUncertainTrustPaths: false,
        );


        $authResponse = $jrp->parseGetResponse(self::read($dir, 'auth-res'));
        $authCred = $authResponse->verify(
            self::getChallengeFromVector($dir, 'auth-req'),
            $rp,
            $cred,
        );

        // This is mostly testing that known-good challenges are passing. Might
        // want to add some data mangling to also assert failures.
        self::assertSame($metadata['id'], $authCred->getId()->toBase64Url(), 'Auth: Credential ID wrong');
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
            if (is_dir($dir)) {
                $out[$dir] = [$dir];
            }
        }
        return $out;
    }

    private static function getChallengeFromVector(string $dir, string $file): ChallengeLoaderInterface
    {
        $request = self::read($dir, $file);
        assert(is_array($request['publicKey']));
        assert(is_string($request['publicKey']['challenge']));
        return new TestUtilities\TestVectorChallengeLoader($request['publicKey']['challenge']);
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
