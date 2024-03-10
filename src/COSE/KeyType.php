<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\COSE;

/**
 * @link https://www.rfc-editor.org/rfc/rfc9053.html
 * @see §7, table 17
 *
 * @link https://www.iana.org/assignments/cose/cose.xhtml#key-type
 */
enum KeyType: int
{
    // case OctetKeyPair = 1;
    case EllipticCurve = 2;
    case Rsa = 3;
    // case Symmetric = 4;
    // case Reserved = 0;
}
