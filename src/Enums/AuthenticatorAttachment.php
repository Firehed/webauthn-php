<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Enums;

enum AuthenticatorAttachment: string
{
    case CrossPlatform = 'cross-platform';
    case Platform = 'platform';
}
