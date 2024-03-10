<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\COSE;

use GMP;
use UnhandledMatchError;

use function gmp_init;

/**
 * @link https://www.rfc-editor.org/rfc/rfc9053.html
 * @see §7.1, table 18
 *
 * @link https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
 */
enum Curve: int
{
    // OIDs: RFC5840 §2.1.1.1

    // secp256r1 = 1.2.840.10045.3.1.7
    case P256 = 1; // EC2

    // secp384r1 = 1.3.132.0.34
    case P384 = 2; // EC2

    // secp521r1 = 1.3.132.0.35
    case P521 = 3; // EC2 (*not* 512)

    case X25519 = 4; // OKP

    case X448 = 5; // OKP

    case ED25519 = 6; // OKP

    case ED448 = 7; // OKP

    // RFC 5480
    // §2.1.1.1 OIDs for named curves
    public function getOid(): string
    {
        return match ($this) {
            self::P256 => '1.2.840.10045.3.1.7',
            default => throw new UnhandledMatchError('Curve unsupported'),
        };
    }

    // Curve parameters:
    // https://www.secg.org/sec2-v2.pdf
    public function getA(): GMP
    {
        return match ($this) {
            self::P256 => gmp_init('0xFFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFC'),
            default => throw new UnhandledMatchError('Curve unsupported'),
        };
    }

    public function getB(): GMP
    {
        return match ($this) {
            self::P256 => gmp_init('0x5AC635D8 AA3A93E7 B3EBBD55 769886BC 651D06B0 CC53B0F6 3BCE3C3E 27D2604B'),
            default => throw new UnhandledMatchError('Curve unsupported'),
        };
    }

    public function getP(): GMP
    {
        return match ($this) {
            self::P256 => gmp_init('0xFFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFF'),
            default => throw new UnhandledMatchError('Curve unsupported'),
        };
    }
}
