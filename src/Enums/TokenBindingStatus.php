<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Enums;

enum TokenBindingStatus: string
{
    case Present = 'present';
    case Supported = 'supported';
}
