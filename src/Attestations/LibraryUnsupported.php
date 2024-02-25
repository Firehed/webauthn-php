<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Attestations;

use Firehed\WebAuthn\AuthenticatorData;
use Firehed\WebAuthn\BinaryString;

class LibraryUnsupported implements AttestationStatementInterface
{
    /**
     * @param mixed[] $data
     */
    public function __construct(private array $data)
    {
    }

    public function verify(AuthenticatorData $data, BinaryString $clientDataHash): VerificationResult
    {
        return new VerificationResult(AttestationType::Uncertain);
    }
}
