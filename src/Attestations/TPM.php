<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Attestations;

use Firehed\WebAuthn\AuthenticatorData;
use Firehed\WebAuthn\BinaryString;

class TPM implements AttestationStatementInterface
{
    public function __construct(
        private array $data,
    ) {
    }

    public function verify(AuthenticatorData $data, BinaryString $clientDataHash): VerificationResult
    {

        print_r($this);
        print_r($data);
        print_r($clientDataHash);
    }
}
