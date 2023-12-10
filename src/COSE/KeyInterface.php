<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\COSE;

use Firehed\WebAuthn\PublicKey\PublicKeyInterface;

interface KeyInterface
{
    public function getAlgorithm(): Algorithm;

    public function getPublicKey(): PublicKeyInterface;
}
