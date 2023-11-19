<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Codecs;

use Firehed\WebAuthn\BinaryString;
use Firehed\WebAuthn\COSEKey;
use Firehed\WebAuthn\CredentialInterface;
use Firehed\WebAuthn\Credential as CredentialObj;
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
    public function encode(CredentialInterface $credential): string
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

    public function encodeV2(CredentialInterface $credential): string
    {
        $version = 2;

        $type = Enums\PublicKeyCredentialType::PublicKey;
        $id = $credential->getId();
        $publicKey = $credential->getCoseCbor();
        $signCount = $credential->getSignCount();
        $uvInitialized = $credential->isUvInitialized();
        $transports = $credential->getTransports();
        $backupEligible = $credential->isBackupEligible();
        $backupState = $credential->isBackedUp();

        $ao = $credential->getAttestationObject();
        $aCDJ = $credential->getAttestationClientDataJSON();
    }

    public function decode(string $encoded): CredentialInterface
    {
        $binary = base64_decode($encoded, true);
        assert($binary !== false);

        $bytes = new BinaryString($binary);

        $version = $bytes->readUint8();
        assert(($version & 0x80) === 0, 'High bit in version must not be set');
        // match -> decodeV1 ?
        assert($version === 1);

        $idLength = $bytes->readUint16();
        $id = $bytes->read($idLength);

        $cborLength = $bytes->readUint32();
        $cbor = $bytes->read($cborLength);

        $signCount = $bytes->readUint32();

        return new CredentialObj(
            type: Enums\PublicKeyCredentialType::PublicKey,
            id: new BinaryString($id),
            coseKey: new COSEKey(new BinaryString($cbor)),
            signCount: $signCount,
            // No way to know these from existing data.
            isBackedUp: false,
            isBackupEligible: false,
            isUvInitialized: false, // should have been stored :(
            transports: [],
        );
    }
}
