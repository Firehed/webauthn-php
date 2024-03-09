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
        // print_r($this);
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

    // https://www.identityblog.com/?p=389
    public function getPemFormatted(): string
    {
        // Like EllipticCurve, lots of spooky ASN.1 magic.
        $expEnc = self::asn1(0x02, $this->e->unwrap());
        $modEnc = self::asn1(0x02, $this->n->unwrap());
        $seqEnc = self::asn1(0x30, $modEnc . $expEnc);
        $bitEnc = self::asn1(0x03, $seqEnc);
        $algId = pack('H*', '300D06092A864886F70D0101010500');
        // 30 0D // Sequence, legnth 13
        //   06 09 // OID, length 9
        //     2A 86 48 86 F7 0D 01 01 01 //  1.2.840.113549.1.1.1 (RSA)
        //   05 00 // Null, length 0
        $der = self::asn1(0x30, $algId . $bitEnc); // sequence, alg id and components

        $pem  = "-----BEGIN PUBLIC KEY-----\n";
        $pem .= chunk_split(base64_encode($der), 64, "\n");
        $pem .= "-----END PUBLIC KEY-----";

        // echo $pem;
        return $pem;
    }

    private static function asn1(int $type, string $string): string
    {
        switch ($type) {
            case 0x02: // integer
                if (ord($string) > 0x7f) {
                    $string = chr(0) . $string;
                };
                break;
            case 0x03: // bit string
                $string = chr(0) . $string;
                break;
        }
        $length = strlen($string);
        if ($length < 0x80) {
            return sprintf('%c%c%s', $type, $length, $string);
        } elseif ($length < 0x0100) {
            return sprintf('%c%c%c%s', $type, 0x81, $length, $string);
        } elseif ($length < 0x010000) {
            return sprintf('%c%c%c%c%s', $type, 0x82, $length / 0x0100, $length % 0x0100, $string);
        }
        throw new \OverflowException('Cannot encode a value that big');
    }
}
