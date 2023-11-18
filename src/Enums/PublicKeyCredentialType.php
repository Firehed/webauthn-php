<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Enums;

enum PublicKeyCredentialType: string
{
    case PublicKey = 'public-key';
}
