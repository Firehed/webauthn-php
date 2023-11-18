<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Enums;

enum AuthenticatorTransport: string
{
    case Ble = 'ble';
    case SmartCard = 'smart-card';
    case Hybrid = 'hybrid';
    case Internal = 'internal';
    case Nfc = 'nfc';
    case Usb = 'usb';
}
