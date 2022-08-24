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
    public function __construct(
        private readonly BinaryString $id,
        private readonly COSEKey $coseKey,
        private readonly int $signCount,
    ) {
    }

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
            $this->id,
            $this->coseKey,
            $newSignCount,
        );
    }
}
