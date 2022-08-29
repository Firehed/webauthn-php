<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Errors;

/**
 * Errors that can occur during Registring a New Credential
 * @see section 7.1
 * @link https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential
 */
class RegistrationError extends SecurityError
{
}
