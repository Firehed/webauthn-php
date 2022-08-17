<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\PublicKey;

/**
 * @internal
 */
interface PublicKeyInterface
{
    public function getPemFormatted(): string;
}
