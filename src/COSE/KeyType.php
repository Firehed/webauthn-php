<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\COSE;

/**
 * @link https://www.rfc-editor.org/rfc/rfc8152.html
 * @see Section 13, table 21
 */
enum KeyType: int
{
    case OctetKeyPair = 1;
    case EllipticCurve = 2;
    case Symmetric = 4;
    case Reserved = 0;
}
