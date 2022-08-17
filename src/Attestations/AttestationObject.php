<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Attestations;

use Firehed\WebAuthn\AuthenticatorData;

class AttestationObject
{
    public function __construct(
        public readonly AuthenticatorData $data,
        public readonly AttestationStatementInterface $stmt,
    ) {
    }

    /**
     * @param string $hash the sha256 hash (raw) of clientDataJson
     */
    public function verify(string $hash)
    {
        return $this->stmt->verify($this->data, $hash);
    }
}
