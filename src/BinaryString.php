<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

class BinaryString
{
    public function __construct(
        private string $wrapped,
    ) {
    }

    public function __debugInfo()
    {
        return [
            'wrapped' => '0x' .  bin2hex($this->wrapped),
        ];
    }

    public function unwrap(): string
    {
        return $this->wrapped;
    }
}
