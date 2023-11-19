<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

/**
 * @internal
 */
class Credential implements CredentialInterface
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
        private readonly bool $uvInitialized,
        private readonly bool $isBackupEligible,
        private readonly bool $isBackedUp,
        // AO, CDJ?
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

    public function isBackupEligible(): bool
    {
        return $this->isBackupEligible;
    }

    public function isBackedUp(): bool
    {
        return $this->isBackedUp;
    }

    public function withUpdatedSignCount(int $newSignCount): CredentialInterface
    {
        return new Credential(
            $this->type,
            $this->id,
            $this->coseKey,
            $newSignCount,
            $this->transports,
            $this->uvInitialized,
            $this->isBackupEligible,
            $this->isBackedUp,
        );
    }
}
