<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

/**
 * @link https://w3c.github.io/webauthn/#enum-userVerificationRequirement
 *
 * @api
 */
enum UserVerificationRequirement
{
    case Required;
    case Preferred;
    case Discouraged;
}
