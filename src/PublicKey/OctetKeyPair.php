<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\PublicKey;

use DomainException;
use Firehed\WebAuthn\BinaryString;
use Firehed\WebAuthn\COSE;
use Firehed\WebAuthn\COSEKey;
use Sop\ASN1\Type as ASN;

/**
 * @internal
 *
 * @see RFC 8037 (COSE OKP key type)
 * @link https://www.rfc-editor.org/rfc/rfc8037
 *
 * @see RFC 8410 (Algorithm Identifiers for Ed25519, Ed448, X25519, X448)
 * @link https://www.rfc-editor.org/rfc/rfc8410
 */
class OctetKeyPair implements PublicKeyInterface
{
    // CBOR decoding: RFC 9053 §7.2
    private const INDEX_CURVE = -1;
    private const INDEX_X_COORDINATE = -2;

    /** @var array<int, int> Expected public key sizes in bytes */
    private const KEY_SIZES = [
        COSE\Curve::ED25519->value => 32,
        COSE\Curve::ED448->value => 57,
    ];

    public function __construct(
        private COSE\Curve $curve,
        private BinaryString $x,
    ) {
        $expectedSize = self::KEY_SIZES[$curve->value]
            ?? throw new DomainException('Unsupported OKP curve: ' . $curve->value);
        if ($x->getLength() !== $expectedSize) {
            throw new DomainException("Public key not $expectedSize bytes");
        }
    }

    /**
     * @param mixed[] $decoded
     */
    public static function fromDecodedCbor(array $decoded): OctetKeyPair
    {
        // Checked upstream, but re-verify
        assert(array_key_exists(COSEKey::INDEX_KEY_TYPE, $decoded));
        assert(is_int($decoded[COSEKey::INDEX_KEY_TYPE]));
        $type = COSE\KeyType::from($decoded[COSEKey::INDEX_KEY_TYPE]);
        assert($type === COSE\KeyType::OctetKeyPair);

        assert(array_key_exists(COSEKey::INDEX_ALGORITHM, $decoded));
        assert(is_int($decoded[COSEKey::INDEX_ALGORITHM]));
        $algorithm = COSE\Algorithm::from($decoded[COSEKey::INDEX_ALGORITHM]);
        if ($algorithm !== COSE\Algorithm::EdDSA && $algorithm !== COSE\Algorithm::Ed448) {
            throw new DomainException('Unsupported OKP algorithm: ' . $algorithm->value);
        }

        assert(is_int($decoded[self::INDEX_CURVE]));
        $curve = COSE\Curve::from($decoded[self::INDEX_CURVE]);
        if (!isset(self::KEY_SIZES[$curve->value])) {
            throw new DomainException('Unsupported OKP curve: ' . $curve->value);
        }

        assert(is_string($decoded[self::INDEX_X_COORDINATE]));
        $x = new BinaryString($decoded[self::INDEX_X_COORDINATE]);

        return new OctetKeyPair(curve: $curve, x: $x);
    }

    // RFC 8410 §4
    public function getPemFormatted(): string
    {
        // SubjectPublicKeyInfo per RFC 8410 §4
        $asn = new ASN\Constructed\Sequence(
            new ASN\Constructed\Sequence(
                new ASN\Primitive\ObjectIdentifier($this->curve->getOid()),
            ),
            new ASN\Primitive\BitString($this->x->unwrap()),
        );
        $der = $asn->toDER();

        $pem  = "-----BEGIN PUBLIC KEY-----\n";
        $pem .= chunk_split(base64_encode($der), 64, "\n");
        $pem .= "-----END PUBLIC KEY-----";
        return $pem;
    }
}
