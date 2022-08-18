<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

// internal except for serialization??
class Credential
{
    public function __construct(
        public readonly BinaryString $id,
        public readonly COSEKey $coseKey,
        public readonly int $signCount,
    ) {
    }

    // TODO: getStorageSafeId?
    public function getSafeId(): string
    {
        return bin2hex($this->id->unwrap());
    }

    /**
     * @internal
     */
    public function getPublicKey(): PublicKey\PublicKeyInterface
    {
        return $this->coseKey->getPublicKey();
    }
}
