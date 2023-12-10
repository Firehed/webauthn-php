<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Codecs;

use Firehed\WebAuthn\Attestations\AttestationObject;
use Firehed\WebAuthn\BinaryString;
use Firehed\WebAuthn\COSEKey;
use Firehed\WebAuthn\CredentialInterface;
use Firehed\WebAuthn\CredentialV1;
use Firehed\WebAuthn\CredentialV2;
use Firehed\WebAuthn\Enums;
use UnhandledMatchError;

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
 * All integer formats are big-endian.
 *
 * Format spec:
 *
 * A CredentialObj shall be encoded to a string.
 * That string shall be a base64-encoded representation of:
 *
 * [ version ] [ version-specific data ]
 *
 * version shall be a single byte.
 * The highest bit shall be 0.
 * A high bit of 1 is reserved for future use, and if encountered, an error
 * should be thrown.
 * The lowest seven bits shall be interpreted as a 7-bit integer (i.e. 00-7F).
 *
 * The remainder of the string is a variable-length value that is specific to
 * the version.
 *
 * @api
 */
class Credential
{
    private const TRANPSORT_FLAGS = [
        0 => Enums\AuthenticatorTransport::Ble,
        1 => Enums\AuthenticatorTransport::Hybrid,
        2 => Enums\AuthenticatorTransport::Internal,
        3 => Enums\AuthenticatorTransport::Nfc,
        4 => Enums\AuthenticatorTransport::SmartCard,
        5 => Enums\AuthenticatorTransport::Usb,
    ];

    private const PACK_UINT8 = 'C';
    private const PACK_UINT16 = 'n';
    private const PACK_UINT32 = 'N';

    public function __construct(
        private readonly bool $storeRegistrationData = true,
    ) {
    }

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
     * id legnth is an unsigned short (16bit)
     * id is a string of variable length [id length]
     * coseKeyLength is an unsigned long (32bit)
     * coseKeyCbor is a string of variable legnth [coseKeyCbor]
     * signCount is an unsigned long (32bit)
     *
     */
    private function encodeV1(CredentialInterface $credential): string
    {
        $version = 1;

        $rawId = $credential->getId()->unwrap();
        $rawCbor = $credential->getCoseCbor()->unwrap();

        $versionSpecificFormat = sprintf(
            '%s%s%s%s%s',
            pack(self::PACK_UINT16, strlen($rawId)),
            $rawId,
            pack(self::PACK_UINT32, strlen($rawCbor)),
            $rawCbor,
            pack(self::PACK_UINT32, $credential->getSignCount()),
        );

        // append a checksum (crc32?) that import can validate?
        // e.g. assert(crc32(substr(data, 1, -4)) === substr(data, -4))

        $binary = pack(self::PACK_UINT8, $version) . $versionSpecificFormat;

        return base64_encode($binary);
    }

    /**
     * Version 2:
     *
     * [ flags ] [ idLength ] [ id ] [ signCount ] [ coseKeyLength ] [ coseKey
     * ] [ transports ] [ attestationData ]
     * Flags: 1 byte where bit 0 is the least significant bit
     *   0: UV is initialized
     *   1: Backup Eligible
     *   2: Backup State
     *   3: Transports included
     *   4: Attestation Data included
     *   5-7: RFU
     *
     * Transports: if [flags] has bit 3 set, the next byte tracks supported
     * authenticator transports. If flags bit 3 is not set, the transports byte
     * will be skipped.
     *   0-5: see TRANSPORT_FLAGS
     *   6: Reserved for Future Use (RFU1)
     *   7: Reserved for Future Use (RFU2)
     *
     * Attestation Data: if [flags] has bit 4 set, a tuple follows:
     * - aoLength (u32)
     * - cdjLength (u32)
     * - aoData - string of length `aoLength`
     * - clientDataJSON - string of legnth `cdjLength`
     *
     * Note: this has CBOR and JSON inside of a packed format, which is a bit
     * strange. A v3 of this codec may use a pure-CBOR representation which
     * should be marginally more efficient.
     *
     * This capures all of the recommended Credential Record data as of
     * WebAuthn Level 3 (except `type` which only has one value).
     *
     * @link https://www.w3.org/TR/webauthn-3/#credential-record
     */
    private function encodeV2(CredentialInterface $credential): string
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

        $attestationData = $credential->getAttestationData();
        if ($attestationData !== null && $this->storeRegistrationData) {
            $flags |= (1 << 4);
            [$ao, $aCDJ] = $attestationData;
            $aoData = $ao->getCbor();
            $aoLength = $aoData->getLength();
            $cdjLenth = $aCDJ->getLength();

            $attestation = sprintf(
                '%s%s%s%s',
                pack(self::PACK_UINT32, $aoLength),
                pack(self::PACK_UINT32, $cdjLenth),
                $aoData->unwrap(),
                $aCDJ->unwrap(),
            );
        } else {
            $attestation = '';
        }

        $rawId = $credential->getId()->unwrap();
        $rawCbor = $credential->getCoseCbor()->unwrap();
        $signCount = $credential->getSignCount();

        assert($flags >= 0x00 && $flags <= 0xFF); // @phpstan-ignore-line
        $versionSpecificFormat = sprintf(
            '%s%s%s%s%s%s%s%s',
            pack(self::PACK_UINT8, $flags),
            pack(self::PACK_UINT16, strlen($rawId)),
            $rawId,
            pack(self::PACK_UINT32, $credential->getSignCount()),
            pack(self::PACK_UINT32, strlen($rawCbor)),
            $rawCbor,
            $transportFlags > 0 ? pack(self::PACK_UINT8, $transportFlags) : '',
            $attestation,
        );

        $binary = pack(self::PACK_UINT8, $version) . $versionSpecificFormat;

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
            default => throw new UnhandledMatchError('Unsupported version'),
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

        // 0x10: attData
        $AT = ($flags & 0x10) === 0x10;
        if ($AT) {
            $aoLength = $bytes->readUint32();
            $cdjLength = $bytes->readUint32();
            $rawAo = $bytes->read($aoLength);
            $cdj = new BinaryString($bytes->read($cdjLength));
            $ao = new AttestationObject(new BinaryString($rawAo));
            $attestation = [$ao, $cdj];
        } else {
            $attestation = null;
        }

        return new CredentialV2(
            type: Enums\PublicKeyCredentialType::PublicKey,
            id: new BinaryString($id),
            transports: $transports,
            signCount: $signCount,
            isUvInitialized: $UV,
            isBackupEligible: $BE,
            isBackedUp: $BS,
            coseKey: new COSEKey(new BinaryString($cbor)),
            attestation: $attestation,
        );
    }
}
