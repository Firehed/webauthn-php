<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Attestations;

class Tpm
{
    public function __construct(
        private array $data,
    ) {
    }

}
