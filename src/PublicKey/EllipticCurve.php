<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\PublicKey;

use Firehed\WebAuthn\BinaryString;
use UnexpectedValueException;

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
    public function __construct(private BinaryString $x, private BinaryString $y)
    {
        if ($x->getLength() !== 32) {
            throw new UnexpectedValueException('X-coordinate not 32 bytes');
        }
        if ($y->getLength() !== 32) {
            throw new UnexpectedValueException('Y-coordinate not 32 bytes');
        }
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
        // Described in RFC 5480
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
}
