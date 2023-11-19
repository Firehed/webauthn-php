<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

/**
 * @covers Firehed\WebAuthn\AuthenticatorData
 */
class AuthenticatorDataTest extends \PHPUnit\Framework\TestCase
{
    public function testParseAssertion(): void
    {
        $bytes = BinaryString::fromBytes([
            73, 150, 13, 229, 136, 14, 140, 104,
            116, 52, 23, 15, 100, 118, 96, 91,
            143, 228, 174, 185, 162, 134, 50, 199,
            153, 92, 243, 186, 131, 29, 151, 99, // RP ID Hash
            5, // Flags: 0x01 | 0x04
            0, 0, 0, 0, // Sign count
        ]);
        $ad = AuthenticatorData::parse($bytes);
        self::assertSame(
            hash('sha256', 'localhost', true),
            $ad->getRpIdHash()->unwrap(),
            'RP ID should match localhost',
        );
        self::assertTrue($ad->isUserPresent(), 'Flags bit 0 is set, UP=true');
        self::assertTrue($ad->isUserVerified(), 'Flags bit 2 is set, UV=true');
        self::assertSame(0, $ad->getSignCount(), 'Sign count should be zero');
        try {
            $_ = $ad->getAttestedCredentialData();
            self::fail('AuthData does not include an attested credential');
        } catch (\Throwable) {
        }
    }

    public function testParseAttestation(): void
    {
        $bytes = BinaryString::fromBytes([
            73, 150, 13, 229, 136, 14, 140, 104,
            116, 52, 23, 15, 100, 118, 96, 91,
            143, 228, 174, 185, 162, 134, 50, 199,
            153, 92, 243, 186, 131, 29, 151, 99, // RP ID Hash
            69, // Flags: 0x01 | 0x04 | 0x40
            0, 0, 0, 0, // Sign count
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, // ACD: AAGUID
            0, 20, // ACD: CredentialIdLength
            120, 102, 86, 81, 105, 128, 125, 50, 94, 122,
            211, 30, 143, 233, 218, 41, 221, 208, 243, 220, // CredentialId
            // CBOR ~ credential
            165, 1, 2, 3, 38, 32, 1, 33,
            88, 32, 5, 81, 213, 60, 195, 89,
            194, 44, 6, 30, 204, 225, 155, 138,
            165, 233, 1, 88, 229, 160, 11, 55,
            166, 185, 176, 49, 249, 242, 249, 75,
            164, 250, 34, 88, 32, 42, 223, 106,
            109, 245, 194, 33, 47, 117, 146, 238,
            140, 190, 130, 26, 152, 23, 67, 242,
            26, 141, 134, 85, 72, 57, 59, 250,
            231, 47, 223, 219, 52,
        ]);

        $ad = AuthenticatorData::parse($bytes);
        self::assertSame(
            hash('sha256', 'localhost', true),
            $ad->getRpIdHash()->unwrap(),
            'RP ID should match localhost',
        );
        self::assertTrue($ad->isUserPresent(), 'Flags bit 0 is set, UP=true');
        self::assertTrue($ad->isUserVerified(), 'Flags bit 2 is set, UV=true');
        $_ = $ad->getAttestedCredentialData(); // Checking that this doesn't throw.
    }

    public function testParseAssertionWithNoFlags(): void
    {
        $bytes = BinaryString::fromBytes([
            73, 150, 13, 229, 136, 14, 140, 104,
            116, 52, 23, 15, 100, 118, 96, 91,
            143, 228, 174, 185, 162, 134, 50, 199,
            153, 92, 243, 186, 131, 29, 151, 99, // RP ID Hash
            0, // Flags: empty!
            0, 0, 1, 2, // Sign count
        ]);
        $ad = AuthenticatorData::parse($bytes);
        self::assertSame(
            hash('sha256', 'localhost', true),
            $ad->getRpIdHash()->unwrap(),
            'RP ID should match localhost',
        );
        self::assertFalse($ad->isUserPresent(), 'Flags bit 0 is not set, UP=false');
        self::assertFalse($ad->isUserVerified(), 'Flags bit 2 is not set, UV=false');
        self::assertSame(258, $ad->getSignCount(), 'Sign count wrong');
        try {
            $_ = $ad->getAttestedCredentialData();
            self::fail('AuthData does not include an attested credential');
        } catch (\Throwable) {
        }
    }
}
