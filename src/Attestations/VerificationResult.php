<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Attestations;

use Firehed\WebAuthn\Certificate;

/**
 * @internal
 *
 * @see 6.5.2
 * @link https://www.w3.org/TR/webauthn-2/#sctn-attestation-formats
 */
class VerificationResult
{
    /**
     * @param Certificate[] $trustPath A list of (binary form for now?) X.509
     * Certificates
     */
    public function __construct(
        public readonly AttestationType $type,
        public readonly array $trustPath = [],
    ) {
    }
}
