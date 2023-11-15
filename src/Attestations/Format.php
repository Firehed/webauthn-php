<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Attestations;

/**
 * @link https://www.iana.org/assignments/webauthn/webauthn.xhtml
 */
enum Format: string
{
    case AndroidKey = 'android-key';
    case AndroidSafetyNet = 'android-safetynet';
    case Apple = 'apple';
    case None = 'none';
    case Packed = 'packed';
    case TPM = 'tpm';
    case U2F = 'fido-u2f';
}
