<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\COSE;

/**
 * @link https://www.rfc-editor.org/rfc/rfc8152.html
 * @see Section 13, table 21
 *
 * This has expanded in RFC9053 and https://www.iana.org/assignments/cose/cose.xhtml
 *
 * https://www.iana.org/assignments/cose/cose.xhtml#key-type
 */
enum KeyType: int
{
    public const COSE_INDEX = 1;

    case OctetKeyPair = 1;
    case EllipticCurve = 2;
    case Rsa = 3;
    case Symmetric = 4;
    case HssLms = 5;
    case WalnutDsa = 6;
    case Reserved = 0;
}
