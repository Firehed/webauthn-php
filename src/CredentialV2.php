<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

/**
 * @phpstan-type AttestationTuple array{
 *   Attestations\AttestationObjectInterface,
 *   BinaryString,
 * }
 *
 * @internal
 */
class CredentialV2 implements CredentialInterface
{
    // Risk factors:
    //   Create:
    //    - attestation unacceptable under RP policy
    //    - certificate chain
    //   Get:
    //     - counter bad
    /**
     * @param Enums\AuthenticatorTransport[] $transports
     * @param ?AttestationTuple $attestation,
     */
    public function __construct(
        public readonly Enums\PublicKeyCredentialType $type,
        private readonly BinaryString $id,
        private readonly COSEKey $coseKey,
        private readonly int $signCount,
        private readonly array $transports,
        private readonly bool $isUvInitialized,
        private readonly bool $isBackupEligible,
        private readonly bool $isBackedUp,
        private readonly ?array $attestation,
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

    /** @return Enums\AuthenticatorTransport[] */
    public function getTransports(): array
    {
        return $this->transports;
    }

    public function isBackupEligible(): bool
    {
        return $this->isBackupEligible;
    }

    public function isBackedUp(): bool
    {
        return $this->isBackedUp;
    }

    public function isUvInitialized(): bool
    {
        return $this->isUvInitialized;
    }

    public function getAttestationData(): ?array
    {
        return $this->attestation;
    }

    public function withUpdatedSignCount(int $newSignCount): CredentialInterface
    {
        return new self(
            $this->type,
            $this->id,
            $this->coseKey,
            $newSignCount,
            $this->transports,
            isUvInitialized: $this->isUvInitialized,
            isBackupEligible: $this->isBackupEligible,
            isBackedUp: $this->isBackedUp,
            attestation: $this->attestation,
        );
    }
}
