<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\PublicKey;

use DomainException;
use Firehed\WebAuthn\BinaryString;
use Firehed\WebAuthn\COSE;
use Firehed\WebAuthn\COSEKey;
use Firehed\WebAuthn\Errors\VerificationError;
use Sop\ASN1\Type as ASN;
use UnexpectedValueException;

use function gmp_cmp;
use function gmp_import;

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
    private const OID = '1.2.840.10045.2.1';

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

        $asn = new ASN\Constructed\Sequence(
            new ASN\Constructed\Sequence(
                new ASN\Primitive\ObjectIdentifier(self::OID),
                new ASN\Primitive\ObjectIdentifier($this->curve->getOid()),
            ),
            new ASN\Primitive\BitString(
                "\x04" // Uncompressed
                . $this->x->unwrap()
                . $this->y->unwrap(),
            ),
        );
        $der = $asn->toDER();

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
        $x3 = $x ** 3; // @phpstan-ignore binaryOp.invalid (phpstan/phpstan#12123)
        $ax = $a * $x; // @phpstan-ignore binaryOp.invalid
        $rhs = ($x3 + $ax + $b) % $p; // @phpstan-ignore binaryOp.invalid

        $y2 = $y ** 2; // @phpstan-ignore binaryOp.invalid
        $lhs = $y2 % $p; // @phpstan-ignore binaryOp.invalid

        // Functionaly, `$lhs === $rhs` but avoids reference equality issues
        // w/out having to introduce loose comparision ($lhs == $rhs works)
        return 0 === gmp_cmp($lhs, $rhs);
    }
}
