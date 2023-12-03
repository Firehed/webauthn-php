<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

/**
 * Data format for WebAuthn Level 2 formats which lacked data for backup
 * eligibility and did not track transports. The numerous hardcoded return
 * values are for the unsupported/untracked data.
 *
 * @internal
 */
class CredentialV1 implements CredentialInterface
{
    // Risk factors:
    //   Create:
    //    - attestation unacceptable under RP policy
    //    - certificate chain
    //   Get:
    //     - counter bad
    public function __construct(
        private readonly BinaryString $id,
        private readonly COSEKey $coseKey,
        private readonly int $signCount,
    ) {
    }

    public function getStorageId(): string
    {
        return $this->id->toBase64Url();
    }

    public function getSignCount(): int
    {
        return $this->signCount;
    }

    public function getId(): BinaryString
    {
        return $this->id;
    }

    public function getCoseCbor(): BinaryString
    {
        return $this->coseKey->cbor;
    }

    public function getPublicKey(): PublicKey\PublicKeyInterface
    {
        return $this->coseKey->getPublicKey();
    }

    public function getTransports(): array
    {
        return [];
    }

    public function isBackupEligible(): bool
    {
        return false;
    }

    public function isBackedUp(): bool
    {
        return false;
    }

    public function isUvInitialized(): bool
    {
        return false;
    }

    public function getAttestationData(): ?array
    {
        return null;
    }

    public function withUpdatedSignCount(int $newSignCount): CredentialInterface
    {
        return new self(
            id: $this->id,
            coseKey: $this->coseKey,
            signCount: $newSignCount,
        );
    }
}
