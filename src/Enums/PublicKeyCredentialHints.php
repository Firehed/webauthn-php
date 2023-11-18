<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Enums;

enum PublicKeyCredentialHints: string
{
    case ClientDevice = 'client-device';
    case Hybrid = 'hybrid';
    case SecurityKey = 'security-key';
}
