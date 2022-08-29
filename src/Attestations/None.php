<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Attestations;

use Firehed\WebAuthn\AuthenticatorData;
use Firehed\WebAuthn\BinaryString;

/**
 * @internal
 *
 * @see 8.7
 * @link https://www.w3.org/TR/webauthn-2/#sctn-none-attestation
 */
class None implements AttestationStatementInterface
{
    /**
     * @param array{} $data (None type conveys no statement data)
     */
    public function __construct(
        private array $data,
    ) {
    }

    public function verify(AuthenticatorData $data, BinaryString $clientDataHash): VerificationResult
    {
        assert($this->data === []); // @phpstan-ignore-line
        return new VerificationResult(AttestationType::None);
    }
}
