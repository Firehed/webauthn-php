<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Attestations;

/**
 * @internal
 *
 * @see 6.5.3
 * @link https://www.w3.org/TR/webauthn-2/#sctn-attestation-types
 */
enum AttestationType
{
    case Basic; //  = 'Basic';
    case Self; // = 'Self';
    case AttestationCA; // = 'AttCA';
    case AnonymizationCA; // = 'AnonCA';
    case None; // = 'None';
}
