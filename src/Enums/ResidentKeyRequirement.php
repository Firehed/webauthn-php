<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Enums;

enum ResidentKeyRequirement: string
{
    case Discouraged = 'discouraged';
    case Preferred = 'preferred';
    case Required = 'required';
}
