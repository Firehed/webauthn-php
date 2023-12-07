<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Attestations;

/**
 * @internal
 *
 * @see 6.5.4
 * @link https://www.w3.org/TR/webauthn-3/#sctn-attestation-types
 */
enum AttestationType
{
    case Basic; //  = 'Basic';
    case Self; // = 'Self';
    case AttestationCA; // = 'AttCA';
    case AnonymizationCA; // = 'AnonCA';
    case None; // = 'None';

    // "uncertainty" isn't really clearly defined in the spec, but it's being
    // used here for "the library probably needs to do more work or be given
    // more data"
    case Uncertain;
}
