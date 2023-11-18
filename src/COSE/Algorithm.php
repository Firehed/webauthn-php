<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\COSE;

/**
 * @link https://www.rfc-editor.org/rfc/rfc8152.html
 * @link https://www.iana.org/assignments/cose/cose.xhtml#algorithms
 *
 * @see Section 8.1, table 5
 */
enum Algorithm: int
{
    case EcdsaSha256 = -7;
    case EcdsaSha384 = -35;
    case EcdsaSha512 = -36;
    // section 8.2: EdDSA = -8;
}
