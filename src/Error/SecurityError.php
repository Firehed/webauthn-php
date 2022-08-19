<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Error;

use RuntimeException;

class SecurityError extends RuntimeException
{
    public function __construct(
        public readonly string $section,
        string $message,
    ) {
        parent::__construct($message);
    }
}
