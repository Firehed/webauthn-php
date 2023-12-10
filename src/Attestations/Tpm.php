<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Attestations;

use Exception;
use Firehed\CBOR\Decoder;
use Firehed\WebAuthn\AuthenticatorData;
use Firehed\WebAuthn\BinaryString;
use Firehed\WebAuthn\Certificate;
use Firehed\WebAuthn\PublicKey\EllipticCurve;
use OpenSSLCertificate;

class Tpm implements AttestationStatementInterface
{
    public function __construct(
        private array $data,
    ) {
    }

    public function verify(AuthenticatorData $data, BinaryString $clientDataHash): VerificationResult
    {
    }
}
