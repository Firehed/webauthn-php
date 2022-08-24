<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Error;

use UnexpectedValueException;

class ParseError extends UnexpectedValueException
{
    public function __construct(
        public readonly string $section,
        string $message,
    ) {
        parent::__construct($message);
    }
}
