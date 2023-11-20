<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Codecs;

use Firehed\WebAuthn\BinaryString;
use Firehed\WebAuthn\COSEKey;
use Firehed\WebAuthn\CredentialInterface;
use Firehed\WebAuthn\CredentialV1;
use Firehed\WebAuthn\CredentialV2;
use Firehed\WebAuthn\Enums;

/**
 * This codec is responsible for serializing a CredentialInterface object to
 * and unserializing from a binary-safe string for storage and retreival.
 *
 * Client applications SHOULD NOT attempt to manually encode or decode
 * credentials. The encoded representation of a credential SHOULD be treated as
 * an opaque string without inspection or modification. This library makes
 * the following promises:
 *
 * - The opaque strings will not be outside of the base64 character range
 * (A-Za-z0-9/+=)
 * - The opaque strings are versioned, and if a new version is introduced,
 * there will be an upgrade/conversion path
 * - The opaque strings will not exceed 64KiB (65535 bytes)
 *
 * Client applications must adhere to the following guidelines:
 * - The opaque strings must be stored without modification
 *   - Do not change case
 *   - Do not trim or truncate any bytes
 * - If the opaque strings are stored in a database, the data type must hold at
 * least 64KiB (note: this is intentionally the size of TEXT column in MySQL)
 * - Storage of opaque strings must ensure a byte-for-byte roundtrip after
 * accounting for connection and storage encoding. This is a low-risk area for
 * the base64 character set, by design.
 *
 *
 * The format spec is for internal use only.
 *
 * Format spec:
 *
 * A CredentialObj shall be encoded to a string.
 * That string shall be a base64-encoded representation of:
 *
 * [ version ] [ version-specific data ]
 *
 * version shall be a single byte.
 * The highest bit (big-endian) shall be 0.
 * A high bit of 1 is reserve for future use, and if encountered, an error
 * should be thrown.
 * The lowest seven bits shall be interpreted as a big-endian7-bit integer.
 *
 * The remainder of the string is a variable-length value that is specific to
 * the version.
 *
 * @api
 */
class Credential
{
    public function encode(CredentialInterface $credential): string
    {
        return match (true) {
            $credential instanceof CredentialV1 => $this->encodeV1($credential),
            default => $this->encodeV2($credential),
        };
    }
    /**
     * Version 1:
     *
     * [ id length ] [ id ] [ coseKeyLength ] [ coseKeyCbor ] [ signCount ]
     *
     * id legnth is a big-endian unsigned short (16bit)
     * id is a string of variable length [id length]
     * coseKeyLength is a big-endian unsigned long (32bit)
     * coseKeyCbor is a string of variable legnth [coseKeyCbor]
     * signCount is a big-endian unsigned long (32bit)
     *
     */
    public function encodeV1(CredentialInterface $credential): string
    {
        $version = 1;

        $rawId = $credential->getId()->unwrap();
        $rawCbor = $credential->getCoseCbor()->unwrap();

        $versionSpecificFormat = sprintf(
            '%s%s%s%s%s',
            pack('n', strlen($rawId)),
            $rawId,
            pack('N', strlen($rawCbor)),
            $rawCbor,
            pack('N', $credential->getSignCount()),
        );

        // append a checksum (crc32?) that import can validate?
        // e.g. assert(crc32(substr(data, 1, -4)) === substr(data, -4))

        $binary = pack('C', $version) . $versionSpecificFormat;

        return base64_encode($binary);
    }

    /**
     * Version 2:
     *
     * [ flags ] [ idLength ] [ id ] [ signCount ] [ coseKeyLength ] [ coseKey
     * ] [ transports ]
     * Flags: 1 byte (big-endian), where bit 0 is the least significant big
     *   0: UV is initialized
     *   1: Backup Eligible
     *   2: Backup State
     *   3: Transports included
     *   4: Attestation Object included
     *   5: Attestation Client Data JSON included
     *   6-7: RFU
     *
     * Transports: if [flags] has bit 3 set, the next byte tracks supported
     * authenticator transports. If flags bit 3 is not set, the transports byte
     * will be skipped.
     *   0-5: see TRANSPORT_FLAGS
     *   6: Reserved for Future Use (RFU1)
     *   7: Reserved for Future Use (RFU2)
     */
    public function encodeV2(CredentialInterface $credential): string
    {
        // if ($credential->type !== Enums\PublicKeyCredentialType::PublicKey) {
        // block this for now. May use flags bits to differentiate.
        // }
        $version = 2;

        $flags = 0;
        if ($credential->isUvInitialized()) {
            $flags |= (1 << 0);
        }
        if ($credential->isBackupEligible()) {
            $flags |= (1 << 1);
        }
        if ($credential->isBackedUp()) {
            $flags |= (1 << 2);
        }

        $transportFlags = self::getTransportFlags($credential->getTransports());
        if ($transportFlags !== 0) {
            $flags |= (1 << 3);
        }

        if ($ao = $credential->getAttestationObject()) {
            $flags |= (1 << 4);
        }
        /*
        if ($aCDJ = $credential->getAttestationClientDataJSON()) {
            $flags |= (1 << 5);
        }
         */

        $rawId = $credential->getId()->unwrap();
        $rawCbor = $credential->getCoseCbor()->unwrap();
        $signCount = $credential->getSignCount();

        $versionSpecificFormat = sprintf(
            '%s%s%s%s%s%s%s',
            pack('C', $flags),
            pack('n', strlen($rawId)), // idLength
            $rawId,
            pack('N', $credential->getSignCount()),
            pack('N', strlen($rawCbor)), // coseKeyLength
            $rawCbor,
            $transportFlags > 0 ? pack('C', $transportFlags) : '',
            // AO.length, AO
            // CDJ.length, CDJ
        );

        $binary = pack('C', $version) . $versionSpecificFormat;

        return base64_encode($binary);
    }

    /**
     * @param Enums\AuthenticatorTransport[] $transports
     */
    private static function getTransportFlags(array $transports): int
    {
        $flags = 0;
        foreach ($transports as $transport) {
            $bit = array_search($transport, self::TRANPSORT_FLAGS, true);
            $flags |= (1 << $bit);
        }
        return $flags;
    }

    /**
     * @return Enums\AuthenticatorTransport[]
     */
    private static function parseTransportFlags(int $flags): array
    {
        $transports = [];
        for ($bit = 0; $bit <= 5; $bit++) {
            $value = 1 << $bit;
            if (($flags & $value) === $value) {
                $transports[] = self::TRANPSORT_FLAGS[$bit];
            }
        }
        return $transports;
    }

    private const TRANPSORT_FLAGS = [
        0 => Enums\AuthenticatorTransport::Ble,
        1 => Enums\AuthenticatorTransport::Hybrid,
        2 => Enums\AuthenticatorTransport::Internal,
        3 => Enums\AuthenticatorTransport::Nfc,
        4 => Enums\AuthenticatorTransport::SmartCard,
        5 => Enums\AuthenticatorTransport::Usb,
    ];

    public function decode(string $encoded): CredentialInterface
    {
        $binary = base64_decode($encoded, true);
        assert($binary !== false);

        $bytes = new BinaryString($binary);

        $version = $bytes->readUint8();
        assert(($version & 0x80) === 0, 'High bit in version must not be set');
        return match ($version) {
            1 => $this->decodeV1($bytes),
            2 => $this->decodeV2($bytes),
        };
    }

    private function decodeV1(BinaryString $bytes): CredentialInterface
    {
        $idLength = $bytes->readUint16();
        $id = $bytes->read($idLength);

        $cborLength = $bytes->readUint32();
        $cbor = $bytes->read($cborLength);

        $signCount = $bytes->readUint32();

        return new CredentialV1(
            id: new BinaryString($id),
            coseKey: new COSEKey(new BinaryString($cbor)),
            signCount: $signCount,
        );
    }

    private function decodeV2(BinaryString $bytes): CredentialInterface
    {
        $flags = $bytes->readUint8();

        $idLength = $bytes->readUint16();
        $id = $bytes->read($idLength);

        $signCount = $bytes->readUint32();

        $cborLength = $bytes->readUint32();
        $cbor = $bytes->read($cborLength);

        // 0x01: UV
        $UV = ($flags & 0x01) === 0x01;
        // 0x02: BE
        $BE = ($flags & 0x02) === 0x02;
        // 0x04: BS
        $BS = ($flags & 0x04) === 0x04;

        // 0x08: transports included
        if (($flags & 0x08) === 0x08) {
            $transportFlags = $bytes->readUint8();
            $transports = self::parseTransportFlags($transportFlags);
        } else {
            $transports = [];
        }
        // 0x10: AO
        // 0x20: ACDJ

        return new CredentialV2(
            type: Enums\PublicKeyCredentialType::PublicKey,
            id: new BinaryString($id),
            transports: $transports,
            signCount: $signCount,
            isUvInitialized: $UV,
            isBackupEligible: $BE,
            isBackedUp: $BS,
            coseKey: new COSEKey(new BinaryString($cbor)),
        );
    }
}
