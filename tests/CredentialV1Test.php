<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

/**
 * @covers Firehed\WebAuthn\CredentialV1
 */
class CredentialV1Test extends \PHPUnit\Framework\TestCase
{
    public function testAccessors(): void
    {
        $pk = self::createMock(PublicKey\PublicKeyInterface::class);
        $coseKey = self::createMock(COSEKey::class);
        $coseKey->method('getPublicKey')
            ->willReturn($pk);
        $credential = new CredentialV1(
            id: BinaryString::fromHex('B0BACAFE'),
            coseKey: $coseKey,
            signCount: 10,
        );

        self::assertSame(10, $credential->getSignCount(), 'Sign count wrong');
        self::assertTrue(BinaryString::fromHex('B0BACAFE')->equals($credential->getId()), 'ID changed');
        // Leaving out the COSEey CBOR for now...tat needs work!
        self::assertSame($pk, $credential->getPublicKey(), 'PubKey changed');
        // This test is flexible...storageId needs to be kept stable but the
        // pre-1.0 version could change before final release
        self::assertSame('sLrK_g', $credential->getStorageId(), 'Storage ID wrong');

        self::assertFalse($credential->isBackupEligible(), 'Backup tracking not in format');
        self::assertFalse($credential->isBackedUp(), 'Backup tracking not in format');
        self::assertFalse($credential->isUvInitialized(), 'UV tracking not in format');
        self::assertSame([], $credential->getTransports(), 'Transport tracking not in format');
        self::assertNull($credential->getAttestationData(), 'Attestation tracking not in format');
    }

    public function testUpdatingSignCount(): void
    {
        $pk = self::createMock(PublicKey\PublicKeyInterface::class);
        $coseKey = self::createMock(COSEKey::class);
        $coseKey->method('getPublicKey')
            ->willReturn($pk);
        $credential = new CredentialV1(
            id: BinaryString::fromHex('0000'),
            coseKey: $coseKey,
            signCount: 20,
        );
        $new = $credential->withUpdatedSignCount(50);
        self::assertNotSame($credential, $new, 'Credential must not be modified in-place');
        self::assertSame(50, $new->getSignCount(), 'Sign count should match provided value');
        self::assertSame($credential->getStorageId(), $new->getStorageId(), 'Id should stay the same');
        self::assertEquals(
            $credential->getPublicKey(),
            $new->getPublicKey(),
            'COSE key should be the same',
        );
    }
}
