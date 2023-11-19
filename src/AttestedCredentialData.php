<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

/**
 * @internal
 */
class AttestedCredentialData
{
    public function __construct(
        public readonly BinaryString $aaguid,
        public readonly BinaryString $credentialId,
        public readonly COSEKey $coseKey,
    ) {
    }
}
