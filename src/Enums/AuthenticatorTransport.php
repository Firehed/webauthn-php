<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Enums;

enum AuthenticatorTransport
{
    "usb",
    "nfc",
    "ble",
    "smart-card",
    "hybrid",
    "internal"
}
