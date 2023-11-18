<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Enums;

/**
 * @link https://www.iana.org/assignments/cose/cose.xhtml#algorithms
 */
enum CoseAlgorithmIdentifier: int
{
    case Ed25519 = -8;
    case ES256 = -7;
    case RS256 = -257;
}
