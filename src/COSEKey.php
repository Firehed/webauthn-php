<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

use DomainException;
use Firehed\CBOR\Decoder;

/**
 * @internal
 *
 * Data structure for COSE keys
 * This represents the post-CBOR-decoded structure
 *
 * @see RFC 8152
 * @link https://www.rfc-editor.org/rfc/rfc8152.html
 *
 * @see RFC 8230 (RSA key support - not yet implemented)
 *
 * FIXME: decodedCbor can contain binary data ~ x/y/d(privkey)
 * @phpstan-type DecodedCbor array{
 *   1: int,
 *   3?: int,
 *   -1?: int,
 *   -2?: string,
 *   -3?: string,
 *   -4?: string,
 * }
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

    private COSE\KeyType $keyType;
    private COSE\Algorithm $algorithm;
    private COSE\Curve $curve;
    private BinaryString $x;
    private BinaryString $y;

    public function __construct(public readonly BinaryString $cbor)
    {
        $decoder = new Decoder();
        $decodedCbor = $decoder->decode($cbor->unwrap());

        // Note: these limitations may be lifted in the future
        $keyType = COSE\KeyType::tryFrom($decodedCbor[self::INDEX_KEY_TYPE]);
        if ($keyType !== COSE\KeyType::EllipticCurve) {
            throw new DomainException('Only EC2 keys supported');
        }

        $algorithm = COSE\Algorithm::tryFrom($decodedCbor[self::INDEX_ALGORITHM]);
        if ($algorithm !== COSE\Algorithm::EcdsaSha256) {
            throw new DomainException('Only ES256 supported');
        }

        $curve = COSE\Curve::tryFrom($decodedCbor[self::INDEX_CURVE]);
        if ($curve !== COSE\Curve::P256) {
            throw new DomainException('Only curve P-256 (secp256r1) supported');
        }

        $this->keyType = $keyType;
        $this->algorithm = $algorithm;
        $this->curve = $curve;

        if (strlen($decodedCbor[self::INDEX_X_COORDINATE]) !== 32) {
            throw new DomainException('X coordinate not 32 bytes');
        }
        $this->x = new BinaryString($decodedCbor[self::INDEX_X_COORDINATE]);

        if (strlen($decodedCbor[self::INDEX_Y_COORDINATE]) !== 32) {
            throw new DomainException('X coordinate not 32 bytes');
        }
        $this->y = new BinaryString($decodedCbor[self::INDEX_Y_COORDINATE]);
    }

    /**
     * FIXME: this indirection is not desirable
     */
    public function getPublicKey(): PublicKey\PublicKeyInterface
    {
        // These are valid; the internal formats are brittle right now.
        assert($this->keyType === COSE\KeyType::EllipticCurve);
        assert($this->curve === COSE\Curve::P256);
        // This I don't think conveys anything useful. Mostly retained to
        // silence a warning about unused variables.
        assert($this->algorithm === COSE\Algorithm::EcdsaSha256);
        return new PublicKey\EllipticCurve(new BinaryString(sprintf(
            "%s%s%s",
            "\x04",
            $this->x->unwrap(),
            $this->y->unwrap(),
        )));
    }
}
