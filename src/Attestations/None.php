<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Attestations;

use Firehed\WebAuthn\AuthenticatorData;

class None implements AttestationStatementInterface
{
    public function __construct(
        private array $data,
    ) {
    }

    public function verify(AuthenticatorData $data, string $clientDataHash)
    {
        // Nothing to do, per s8.7. Return attestation=none.

        return new Attestation(Attestation::TYPE_NONE);
    }
}
