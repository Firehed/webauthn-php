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
 * Note: this should be more of a parser than an actual data structure,
 * favoring the actual implementations of PublicKeyInterface instead.
 * Currently, the Credential Codec needs access to the raw CBOR since
 * PublicKeys don't have a CBOR encoder (or a different format could be used,
 * but re-inventing a wheel is very undesirable!).
 *
 * @see RFC 8152
 * @link https://www.rfc-editor.org/rfc/rfc8152.html
 *
 * @see RFC 8230 (RSA key support - not yet implemented)
 *
 * @see RFC 9052
 * @link https://www.rfc-editor.org/rfc/rfc9052
 */
class COSEKey
{
    // Data structure indexes
    // @see RFC 9052 §7.1
    public const INDEX_KEY_TYPE = 1;
    public const INDEX_KEY_ID = 2;
    public const INDEX_ALGORITHM = 3;
    public const INDEX_KEY_OPS = 4;
    public const INDEX_BASE_IV = 5;

    private PublicKey\PublicKeyInterface $publicKey;
    // TODO: move to PublicKeyInterface?
    public readonly COSE\Algorithm $algorithm;

    public function __construct(public readonly BinaryString $cbor)
    {
        $decoder = new Decoder();
        $decodedCbor = $decoder->decode($cbor->unwrap());

        // Note: these limitations may be lifted in the future
        $keyType = COSE\KeyType::tryFrom($decodedCbor[self::INDEX_KEY_TYPE]);
        if ($keyType !== COSE\KeyType::EllipticCurve) {
            throw new DomainException('Only EC2 keys supported');
        }

        $this->publicKey = match ($keyType) {
            COSE\KeyType::EllipticCurve => PublicKey\EllipticCurve::fromDecodedCbor($decodedCbor),
        };

        assert(array_key_exists(self::INDEX_ALGORITHM, $decodedCbor));
        $this->algorithm = COSE\Algorithm::from($decodedCbor[self::INDEX_ALGORITHM]);

        // Future: rfc8152/13.2
        // if keytype == .OctetKeyPair, set `x` and `d`
    }

    /**
     * FIXME: this indirection is not desirable
     */
    public function getPublicKey(): PublicKey\PublicKeyInterface
    {
        return $this->publicKey;
    }
}
