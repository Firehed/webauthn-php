<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Firehed\WebAuthn\CredentialV2
 */
class CredentialV2Test extends TestCase
{
    public function testAccessors(): CredentialV2
    {
        $pk = self::createMock(PublicKey\PublicKeyInterface::class);
        $coseKey = self::createMock(COSEKey::class);
        $coseKey->method('getPublicKey')
            ->willReturn($pk);
        $credential = new CredentialV2(
            type: Enums\PublicKeyCredentialType::PublicKey,
            id: BinaryString::fromHex('B0BACAFE'),
            coseKey: $coseKey,
            signCount: 10,
            transports: [
                Enums\AuthenticatorTransport::Internal,
            ],
            isUvInitialized: true,
            isBackupEligible: true,
            isBackedUp: true,
            attestation: null,
        );

        self::assertTrue(BinaryString::fromHex('B0BACAFE')->equals($credential->getId()), 'ID changed');
        self::assertSame(10, $credential->getSignCount(), 'Sign count wrong');
        // Leaving out the COSEey CBOR for now...tat needs work!
        self::assertSame($pk, $credential->getPublicKey(), 'PubKey changed');
        // This test is flexible...storageId needs to be kept stable but the
        // pre-1.0 version could change before final release
        self::assertSame('sLrK_g', $credential->getStorageId(), 'Storage ID wrong');

        self::assertTrue($credential->isBackupEligible(), 'Backup eligible lost');
        self::assertTrue($credential->isBackedUp(), 'Backup state list');
        self::assertTrue($credential->isUvInitialized(), 'UV state list');
        self::assertEqualsCanonicalizing([
            Enums\AuthenticatorTransport::Internal,
        ], $credential->getTransports(), 'Transports lost');
        self::assertNull($credential->getAttestationData(), 'Attestation was not provided');

        return $credential;
    }

    /** @depends testAccessors */
    public function testUpdateSignCount(CredentialV2 $credential): void
    {
        $updated = $credential->withUpdatedSignCount(11);
        self::assertNotSame($credential, $updated, 'Should return new object');
        self::assertSame(11, $updated->getSignCount(), 'Sign count did not update');
    }
}
