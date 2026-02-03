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
            self::P384 => '1.3.132.0.34',
            self::P521 => '1.3.132.0.35',
            default => throw new UnhandledMatchError('Curve unsupported'),
        };
    }

    /**
     * Returns the coordinate size in bytes for this curve.
     */
    public function getCoordinateSize(): int
    {
        return match ($this) {
            self::P256 => 32,
            self::P384 => 48,
            self::P521 => 66,
            default => throw new UnhandledMatchError('Curve unsupported'),
        };
    }

    // Curve parameters:
    // https://www.secg.org/sec2-v2.pdf
    public function getA(): GMP
    {
        return match ($this) {
            self::P256 => gmp_init('0xFFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFC'),
            self::P384 => gmp_init('0xFFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFFFF 00000000 00000000 FFFFFFFC'),
            self::P521 => gmp_init('0x01FF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFC'),
            default => throw new UnhandledMatchError('Curve unsupported'),
        };
    }

    public function getB(): GMP
    {
        return match ($this) {
            self::P256 => gmp_init('0x5AC635D8 AA3A93E7 B3EBBD55 769886BC 651D06B0 CC53B0F6 3BCE3C3E 27D2604B'),
            self::P384 => gmp_init('0xB3312FA7 E23EE7E4 988E056B E3F82D19 181D9C6E FE814112 0314088F 5013875A C656398D 8A2ED19D 2A85C8ED D3EC2AEF'),
            self::P521 => gmp_init('0x0051 953EB961 8E1C9A1F 929A21A0 B68540EE A2DA725B 99B315F3 B8B48991 8EF109E1 56193951 EC7E937B 1652C0BD 3BB1BF07 3573DF88 3D2C34F1 EF451FD4 6B503F00'),
            default => throw new UnhandledMatchError('Curve unsupported'),
        };
    }

    public function getP(): GMP
    {
        return match ($this) {
            self::P256 => gmp_init('0xFFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFF'),
            self::P384 => gmp_init('0xFFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFFFF 00000000 00000000 FFFFFFFF'),
            self::P521 => gmp_init('0x01FF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF'),
            default => throw new UnhandledMatchError('Curve unsupported'),
        };
    }
}
