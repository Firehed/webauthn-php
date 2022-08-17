<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

// internal except for serialization??
class Credential
{
    public function __construct(
        public readonly BinaryString $id,
        private readonly COSEKey $coseKey,
        public readonly int $signCount,
    ) {
    }

    public function getSafeId(): string
    {
        return bin2hex($this->id->unwrap());
    }

    public function getPublicKey(): PublicKey\PublicKeyInterface
    {
        return $this->coseKey->getPublicKey();
    }
    // getPublicKey(): PKI
    // -> make COSEKey implement PKI & move formatter to same?
    // { PKI: getPemFormatted(): string }
}
