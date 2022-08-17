<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Attestations;

use Firehed\WebAuthn\AuthenticatorData;

interface AttestationStatementInterface
{
    public function verify(AuthenticatorData $data, string $clientDataHash);
}
