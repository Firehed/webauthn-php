<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

/**
 * @covers Firehed\WebAuthn\Credential
 */
class CredentialTest extends \PHPUnit\Framework\TestCase
{
    private PublicKey\PublicKeyInterface $pk;
    private Credential $credential;

    public function setUp(): void
    {
        $this->pk = self::createMock(PublicKey\PublicKeyInterface::class);
        $coseKey = self::createMock(COSEKey::class);
        $coseKey->method('getPublicKey')
            ->willReturn($this->pk);
        $this->credential = new Credential(
            type: Enums\PublicKeyCredentialType::PublicKey,
            id: BinaryString::fromHex('FFFF'),
            coseKey: $coseKey,
            signCount: 10,
            isBackupEligible: true,
            isBackedUp: false,
            isUvInitialized: true,
            transports: [
                Enums\AuthenticatorTransport::Usb,
                Enums\AuthenticatorTransport::Internal,
            ],
        );
    }

    public function testAccessors(): void
    {
        self::assertSame(10, $this->credential->getSignCount(), 'Sign count wrong');
        self::assertTrue(BinaryString::fromHex('FFFF')->equals($this->credential->getId()), 'ID changed');
        // Leaving out the COSEey CBOR for now...that needs work!
        self::assertSame($this->pk, $this->credential->getPublicKey(), 'PubKey changed');
        // This test is flexible...storageId needs to be kept stable but the
        // pre-1.0 version could change before final release
        self::assertSame('ffff', $this->credential->getStorageId(), 'Storage ID wrong');
        self::assertTrue($this->credential->isBackupEligible());
        self::assertFalse($this->credential->isBackedUp());
        self::assertEqualsCanonicalizing([
            Enums\AuthenticatorTransport::Usb,
            Enums\AuthenticatorTransport::Internal,
        ], $this->credential->getTransports());
    }

    public function testUpdatingSignCount(): void
    {
        $new = $this->credential->withUpdatedSignCount(50);
        self::assertNotSame($this->credential, $new, 'Credential must not be modified in-place');
        self::assertSame(50, $new->getSignCount(), 'Sign count should match provided value');
        self::assertSame($this->credential->getStorageId(), $new->getStorageId(), 'Id should stay the same');
        self::assertEquals(
            $this->credential->getPublicKey(),
            $new->getPublicKey(),
            'COSE key should be the same',
        );
    }
}
