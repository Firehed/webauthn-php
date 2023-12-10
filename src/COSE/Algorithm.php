<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\COSE;

/**
 * @link https://www.rfc-editor.org/rfc/rfc8152.html
 * @see Section 8.1, table 5
 *
 * https://www.iana.org/assignments/cose/cose.xhtml#algorithms
 */
enum Algorithm: int
{
    public const COSE_INDEX = 3;

    case EcdsaSha256 = -7;
    case EcdsaSha384 = -35;
    case EcdsaSha512 = -36;
    // section 8.2: EdDSA = -8;

    case Rs256 = -257;
}
