<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Enums;

/**
 * @link https://w3c.github.io/webauthn/#enum-userVerificationRequirement
 *
 * @api
 */
enum UserVerificationRequirement: string
{
    case Discouraged = 'discouraged';
    case Preferred = 'preferred';
    case Required = 'required';
}
