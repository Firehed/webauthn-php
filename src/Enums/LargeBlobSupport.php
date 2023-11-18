<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Enums;

enum LargeBlobSupport: string
{
    case Preferred = 'preferred';
    case Required = 'required';
}
