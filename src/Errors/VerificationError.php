<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Errors;

/**
 * Errors that can occur during Verifying an Authentication Assertion
 * @see section 7.2
 * @link https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion
 */

class VerificationError extends SecurityError
{
}
