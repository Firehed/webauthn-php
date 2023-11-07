<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

/**
 * @api
 */
interface RelyingParty
{
    /**
     * Used by steps 7.1.9 and 7.2.13
     *
     * @internal
     */
    public function matchesOrigin(string $clientDataOrigin): bool;

    /**
     * Used by steps 7.1.13 and 7.2.15
     *
     * @internal
     */
    public function permitsRpIdHash(AuthenticatorData $authData): bool;
}
