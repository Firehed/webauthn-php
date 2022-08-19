<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Attestations;

use Firehed\WebAuthn\AuthenticatorData;
use Firehed\WebAuthn\BinaryString;

/**
 * @internal
 */
class None implements AttestationStatementInterface
{
    public function __construct(
        private array $data,
    ) {
    }

    public function verify(AuthenticatorData $data, BinaryString $clientDataHash)
    {
        // Nothing to do, per s8.7. Return attestation=none.

        return new Attestation(Attestation::TYPE_NONE);
    }
}
