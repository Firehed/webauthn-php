<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Attestations;

use Firehed\WebAuthn\{
    AuthenticatorData,
    BinaryString,
};

/**
 * @internal
 */
interface AttestationObjectInterface
{
    public function getAuthenticatorData(): AuthenticatorData;

    public function getCbor(): BinaryString;

    public function verify(BinaryString $clientDataHash): VerificationResult;
}
