<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Enums;

enum AttestationConveyancePreference: string
{
    case Direct = 'direct';
    case Enterprise = 'enterprise';
    case Indirect = 'indirect';
    case None = 'none';
}
