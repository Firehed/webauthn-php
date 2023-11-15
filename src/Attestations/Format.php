<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Attestations;

/**
 * @link https://www.iana.org/assignments/webauthn/webauthn.xhtml
 */
enum Format: string
{
    case None = 'none';
    case U2F = 'fido-u2f';
    // These are defined in the spec but not yet supported by the library, and
    // as such are left disabled for clarity.
    // case AndroidKey = 'android-key';
    // case AndroidSafetyNet = 'android-safetynet';
    // case Apple = 'apple';
    // case Packed = 'packed';
    // case TPM = 'tpm';
}
