<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\COSE;

/**
 * @link https://www.rfc-editor.org/rfc/rfc9053.html
 * @see §2.1, table 1
 *
 * @link https://www.iana.org/assignments/cose/cose.xhtml#algorithms
 */
enum Algorithm: int
{
    case EcdsaSha256 = -7;
    case EcdsaSha384 = -35;
    case EcdsaSha512 = -36;
    // section 8.2: EdDSA = -8;
}
