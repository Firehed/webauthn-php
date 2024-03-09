<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\PublicKey;

use Firehed\WebAuthn\BinaryString;
use Firehed\WebAuthn\COSE;
use Firehed\WebAuthn\COSEKey;

/**
 * @internal
 *
 * @link https://www.rfc-editor.org/rfc/rfc8230.html
 */
class RSA implements PublicKeyInterface
{
    // RFC 8230 §4 table 4
    private const INDEX_MODULUS = -1;
    private const INDEX_PUB_EXPONENT = -2;
    // Other values not relevant

    private function __construct(
        private BinaryString $n,
        private BinaryString $e,
    ) {
        print_r($this);
    }



    /**
     * @param mixed[] $decoded
     */
    public static function fromDecodedCbor(array $decoded): RSA
    {
        // Checked upstream, but re-verify
        assert(array_key_exists(COSEKey::INDEX_KEY_TYPE, $decoded));
        $type = COSE\KeyType::from($decoded[COSEKey::INDEX_KEY_TYPE]);
        assert($type === COSE\KeyType::Rsa);


        assert(array_key_exists(COSEKey::INDEX_ALGORITHM, $decoded));
        $algorithm = COSE\Algorithm::from($decoded[COSEKey::INDEX_ALGORITHM]);
        // TODO: support other algorithms
        if ($algorithm !== COSE\Algorithm::Rs256) {
            throw new \DomainException('Only RS256 is supported');
        }


        assert(array_key_exists(self::INDEX_MODULUS, $decoded));
        $n = new BinaryString($decoded[self::INDEX_MODULUS]);
        assert(array_key_exists(self::INDEX_PUB_EXPONENT, $decoded));
        $e = new BinaryString($decoded[self::INDEX_PUB_EXPONENT]);

        return new RSA(
            n: $n,
            e: $e,
        );
    }

    public function getPemFormatted(): string
    {
    }
}
