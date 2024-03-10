<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\PublicKey;

use DomainException;
use Firehed\WebAuthn\BinaryString;
use Firehed\WebAuthn\COSE;
use Firehed\WebAuthn\COSEKey;
use Firehed\WebAuthn\Errors\VerificationError;
use UnexpectedValueException;

use function gmp_pow;
use function gmp_add;
use function gmp_cmp;
use function gmp_import;
use function gmp_mod;
use function gmp_mul;

/**
 * @internal
 *
 * @see RFC 5480
 * @link https://www.rfc-editor.org/rfc/rfc5480
 *
 * TODO: This presents as a generic EC key structure, but the PemFormatted
 * implementation is specific to the P-256 curve. This should either be renamed
 * to be less generic or support specifying the curve (and specifying the
 * appropriate OID in the formatter).
 */
class EllipticCurve implements PublicKeyInterface
{
    // CBOR decoding: RFC 9053 §7.1.1
    private const INDEX_CURVE = -1; // ECC, OKP
    private const INDEX_X_COORDINATE = -2; // ECC, OKP
    private const INDEX_Y_COORDINATE = -3; // ECC
    private const INDEX_PRIVATE_KEY = -4; // ECC, OKP @phpstan-ignore-line
    // index_key_value = -1 (same as index_curve, for Symmetric)


    public function __construct(
        private COSE\Curve $curve,
        private BinaryString $x,
        private BinaryString $y,
    ) {
        if ($x->getLength() !== 32) {
            throw new UnexpectedValueException('X-coordinate not 32 bytes');
        }
        if ($y->getLength() !== 32) {
            throw new UnexpectedValueException('Y-coordinate not 32 bytes');
        }
        if (!$this->isOnCurve()) {
            throw new VerificationError('5.8.5', 'Point not on curve');
        }
    }

    /**
     * @param mixed[] $decoded
     */
    public static function fromDecodedCbor(array $decoded): EllipticCurve
    {
        // Checked upstream, but re-verify
        assert(array_key_exists(COSEKey::INDEX_KEY_TYPE, $decoded));
        $type = COSE\KeyType::from($decoded[COSEKey::INDEX_KEY_TYPE]);
        assert($type === COSE\KeyType::EllipticCurve);


        assert(array_key_exists(COSEKey::INDEX_ALGORITHM, $decoded));
        $algorithm = COSE\Algorithm::from($decoded[COSEKey::INDEX_ALGORITHM]);
        // TODO: support other algorithms
        if ($algorithm !== COSE\Algorithm::EcdsaSha256) {
            throw new DomainException('Only ES256 is supported');
        }

        $curve = COSE\Curve::from($decoded[self::INDEX_CURVE]);
        // WebAuthn §5.8.5 - cross-reference curve to algorithm
        assert($curve === COSE\Curve::P256);

        if (strlen($decoded[self::INDEX_X_COORDINATE]) !== 32) {
            throw new DomainException('X coordinate not 32 bytes');
        }
        $x = new BinaryString($decoded[self::INDEX_X_COORDINATE]);

        if (strlen($decoded[self::INDEX_Y_COORDINATE]) !== 32) {
            throw new DomainException('X coordinate not 32 bytes');
        }
        $y = new BinaryString($decoded[self::INDEX_Y_COORDINATE]);

        // private key should not be present; ignoring it

        return new EllipticCurve(
            curve: $curve,
            x: $x,
            y: $y,
        );
    }

    /**
     * Returns a 32-byte string representing the 256-bit X-coordinate on the
     * curve
     */
    public function getXCoordinate(): BinaryString
    {
        return $this->x;
    }

    /**
     * Returns a 32-byte string representing the 256-bit Y-coordinate on the
     * curve
     */
    public function getYCoordinate(): BinaryString
    {
        return $this->y;
    }

    // Prepends the pubkey format headers and builds a pem file from the raw
    // public key component
    public function getPemFormatted(): string
    {
        if ($this->curve !== COSE\Curve::P256) {
            throw new DomainException('Only P256 curves can be PEM-formatted so far');
        }
        // Described in RFC 5480
        // §2.1.1.1
        // Just use an OID calculator to figure out *that* encoding
        $der = hex2bin(
            '3059' // SEQUENCE, length 89
                . '3013' // SEQUENCE, length 19
                    . '0607' // OID, length 7
                        . '2a8648ce3d0201' // 1.2.840.10045.2.1 = EC Public Key
                    . '0608' // OID, length 8
                        . '2a8648ce3d030107' // 1.2.840.10045.3.1.7 = P-256 Curve
                . '0342' // BIT STRING, length 66
                    . '00' // prepend with NUL
                    . '04' // uncompressed format
        );
        $der .= $this->x->unwrap();
        $der .= $this->y->unwrap();

        $pem  = "-----BEGIN PUBLIC KEY-----\n";
        $pem .= chunk_split(base64_encode($der), 64, "\n");
        $pem .= "-----END PUBLIC KEY-----";
        return $pem;
    }

    private function isOnCurve(): bool
    {
        // The curve E: y^2 = x^3 + ax + b over Fp is defined by:
        $a = $this->curve->getA();
        $b = $this->curve->getB();
        $p = $this->curve->getP();

        $x = gmp_import($this->x->unwrap());
        $y = gmp_import($this->y->unwrap());

        // This is only tested with P256 (secp256r1) but SHOULD be the same for
        // the other curves (none of which are supported yet)/
        $x3 = gmp_pow($x, 3);
        $ax = gmp_mul($a, $x);
        $rhs = gmp_mod(gmp_add($x3, gmp_add($ax, $b)), $p);

        $y2 = gmp_pow($y, 2);
        $lhs = gmp_mod($y2, $p);

        return 0 === gmp_cmp($lhs, $rhs); // Values match
    }
}
