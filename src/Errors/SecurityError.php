<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Errors;

use RuntimeException;

class SecurityError extends RuntimeException implements WebAuthnErrorInterface
{
    public function __construct(
        public readonly string $section,
        string $message,
    ) {
        parent::__construct($message);
    }
}
