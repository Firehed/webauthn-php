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
        public readonly BinaryString $id,
        private readonly COSEKey $coseKey,
        public readonly int $signCount,
        public readonly array $transports,
        public readonly bool $uvInitialized,
        public readonly bool $backupEligible,
        public readonly bool $backupState,
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

    public function withUpdatedSignCount(int $newSignCount): CredentialInterface
    {
        return new Credential(
            $this->type,
            $this->id,
            $this->coseKey,
            $newSignCount,
            $this->transports,
            $this->uvInitialized,
            $this->backupEligible,
            $this->backupState,
        );
    }
}
