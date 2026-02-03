<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\COSE;

/**
 * @link https://www.rfc-editor.org/rfc/rfc9053.html
 * @see §2.1, table 1
 *
 * @link https://www.iana.org/assignments/cose/cose.xhtml#algorithms
 *
 * Any of these values SHOULD be safe to put in the publicKeyCredParams, but
 * results may vary as not all combinations are thoroughly tested.
 */
enum Algorithm: int
{
    case EcdsaSha256 = -7;
    case EcdsaSha384 = -35;
    case EcdsaSha512 = -36;
    case EdDSA = -8;
    case Ed448 = -53;

    case Rs256 = -257;

    /**
     * Returns the OpenSSL algorithm constant for signature verification.
     */
    public function getOpenSslAlgorithm(): int
    {
        return match ($this) {
            self::EcdsaSha256, self::Rs256 => \OPENSSL_ALGO_SHA256,
            self::EcdsaSha384 => \OPENSSL_ALGO_SHA384,
            self::EcdsaSha512 => \OPENSSL_ALGO_SHA512,
            // EdDSA (Ed25519/Ed448) uses PureEdDSA which performs hashing
            // internally. OpenSSL has no named constant for this; passing
            // 0 tells openssl_verify to skip external digest computation.
            self::EdDSA, self::Ed448 => 0,
        };
    }
}
