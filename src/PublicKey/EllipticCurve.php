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
    public function __construct(private BinaryString $binary)
    {
        $key = $binary->unwrap();
        // RFC5480 2.2 - must be uncompressed value
        if ($key[0] !== "\x04") {
            throw new UnexpectedValueException(
                'EC public key: first byte not x04 (uncompressed)'
            );
        }
        if (strlen($key) !== 65) {
            throw new UnexpectedValueException(
                'EC public key: length is not 65 bytes'
            );
        }
    }

    /**
     * Returns a 32-byte string representing the 256-bit X-coordinate on the
     * curve
     */
    public function getXCoordinate(): string
    {
        $uncompressed = $this->binary->unwrap();
        return substr($uncompressed, 1, 32);
    }

    /**
     * Returns a 32-byte string representing the 256-bit Y-coordinate on the
     * curve
     */
    public function getYCoordinate(): string
    {
        $uncompressed = $this->binary->unwrap();
        return substr($uncompressed, 33, 32);
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
                    . '00' // prepend with NUL - pubkey will follow
        );
        $der .= $this->binary->unwrap();

        $pem  = "-----BEGIN PUBLIC KEY-----\r\n";
        $pem .= chunk_split(base64_encode($der), 64);
        $pem .= "-----END PUBLIC KEY-----";
        return $pem;
    }

    /** @return array{x: string, y: string} */
    public function __debugInfo(): array
    {
        return [
            'x' => '0x' . bin2hex($this->getXCoordinate()),
            'y' => '0x' . bin2hex($this->getYCoordinate()),
        ];
    }
}
