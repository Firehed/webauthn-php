<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

/**
 * Data format for storage of WebAuth Level 2 credentials, which were prior to
 * flags about backup status, etc.
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

    public function withUpdatedSignCount(int $newSignCount): CredentialInterface
    {
        return new CredentialV1(
            $this->id,
            $this->coseKey,
            $newSignCount,
        );
    }
}
