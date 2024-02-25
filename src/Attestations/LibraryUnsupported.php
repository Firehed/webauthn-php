<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Attestations;

use Firehed\WebAuthn\AuthenticatorData;
use Firehed\WebAuthn\BinaryString;

class LibraryUnsupported implements AttestationStatementInterface
{
    public function verify(AuthenticatorData $data, BinaryString $clientDataHash): VerificationResult
    {
        return new VerificationResult(AttestationType::Uncertain);
    }
}
