<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

/**
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
        // optional/required as a pair?
        private readonly ?Attestations\AttestationObjectInterface $ao,
        private readonly ?BinaryString $attestationCDJ,
    ) {
    }

    // FIXME: Move this to base64url
    public function getStorageId(): string
    {
        return bin2hex($this->id->unwrap());
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

    public function getAttestationData(): array
    {
        // if AO or CDJ are null, return null
        return [$this->ao, $this->attestationCDJ];
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
            ao: $this->ao,
            attestationCDJ: $this->attestationCDJ,
        );
    }
}
