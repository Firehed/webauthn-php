<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Errors;

use UnexpectedValueException;

class ParseError extends UnexpectedValueException implements WebAuthnErrorInterface
{
    public function __construct(
        public readonly string $section,
        string $message,
    ) {
        parent::__construct($message);
    }
}
