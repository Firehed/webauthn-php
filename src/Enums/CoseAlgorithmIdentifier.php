<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Enums;

/**
 * @link https://www.iana.org/assignments/cose/cose.xhtml#algorithms
 */
enum CoseAlgorithmIdentifier: int
{
    // There's a LOT of formats. Only enable the supported ones for now.
    case ES256 = -7;
    // case Ed25519 = -8;
    // case RS256 = -257;
}
