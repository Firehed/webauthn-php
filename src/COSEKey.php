<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

use DomainException;

/**
 * @internal
 *
 * Data structure for COSE keys
 * This represents the post-CBOR-decoded structure
 *
 * @see RFC 8152
 * @link https://www.rfc-editor.org/rfc/rfc8152.html
 */
class COSEKey
{
    // Data structure indexes
    // @see section 7.1
    private const INDEX_KEY_TYPE = 1;
    private const INDEX_ALGORITHM = 3;
    // 13.1.1-13.2
    private const INDEX_CURVE = -1; // ECC, OKP
    private const INDEX_X_COORDINATE = -2; // ECC, OKP
    private const INDEX_Y_COORDINATE = -3; // ECC
    private const INDEX_PRIVATE_KEY = -4; // ECC, OKP
    // index_key_value = -1 (same as index_curve, for Symmetric)

    // @see section 13 - these are in INDEX_KEY_TYPE
    private const KEY_TYPE_OKP = 1; // Octet Key Pair
    private const KEY_TYPE_EC2 = 2; // Double coordinate curve
    private const KEY_TYPE_SYMMETRIC = 4;
    private const KEY_TYPE_RESERVED = 0;

    // @see section 8.1 - these are in INDEX_ALGORITHM
    private const ALGORITHM_ECDSA_SHA_256 = -7;
    private const ALGORITHM_ECDSA_SHA_384 = -35;
    private const ALGORITHM_ECDSA_SHA_512 = -36;
    // 8.2: EdDSA = -8;

    // @see section 13.1 - these are in INDEX_CURVE
    private const CURVE_P256 = 1; // EC2
    private const CURVE_P384 = 2; // EC2
    private const CURVE_P521 = 3; // EC2 (*not* 512)
    private const CURVE_X25519 = 4; // OKP
    private const CURVE_X448 = 5; // OKP
    private const CURVE_ED25519 = 6; // OKP
    private const CURVE_ED448 = 7; // OKP


    public function __construct(private array $decodedCbor)
    {
        // Note: these limitations may be lifted in the future
        if ($decodedCbor[self::INDEX_KEY_TYPE] !== self::KEY_TYPE_EC2) {
            throw new DomainException('Only EC2 keys supported');
        }

        if ($decodedCbor[self::INDEX_ALGORITHM] !== self::ALGORITHM_ECDSA_SHA_256) {
            throw new DomainException('Only ES256 supported');
        }

        if ($decodedCbor[self::INDEX_CURVE] !== self::CURVE_P256) {
            throw new DomainException('Only curve P-256 (secp256r1) supported');
        }

        if (strlen($decodedCbor[self::INDEX_X_COORDINATE]) !== 32) {
            throw new DomainException('X coordinate not 32 bytes');
        }
        if (strlen($decodedCbor[self::INDEX_Y_COORDINATE]) !== 32) {
            throw new DomainException('X coordinate not 32 bytes');
        }
    }

    /**
     * FIXME: this is absurd
     * @deprecated
     */
    public function getPublicKey(): PublicKey\PublicKeyInterface
    {
        return new PublicKey\EllipticCurve(sprintf(
            "%s%s%s",
            "\x04",
            $this->decodedCbor[self::INDEX_X_COORDINATE],
            $this->decodedCbor[self::INDEX_Y_COORDINATE],
        ));
    }

    public function __serialize(): array
    {
        return [
            'version' => 1,
            'data' => $this->decodedCbor,
        ];
    }

    public function __unserialize(array $data): void
    {
        assert($data['version'] === 1);
        $this->decodedCbor = $data['data'];
    }
}
