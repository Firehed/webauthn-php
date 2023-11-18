<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Enums;

enum UserVerificationRequirement: string
{
    case Discouraged = 'discouraged';
    case Preferred = 'preferred';
    case Required = 'required';
}
