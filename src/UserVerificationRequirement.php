<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

// https://w3c.github.io/webauthn/#enum-userVerificationRequirement
enum UserVerificationRequirement
{
    case Required;
    case Preferred;
    case Discouraged;
}
