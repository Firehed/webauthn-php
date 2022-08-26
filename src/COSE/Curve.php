<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\COSE;

/**
 * @link https://www.rfc-editor.org/rfc/rfc8152.html
 * @see Section 13.1, table 22
 */
enum Curve: int
{
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
}
