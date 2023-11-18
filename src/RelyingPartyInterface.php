<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

/**
 * @api: All implementations of RelyingParty are considered part of the public
 * API for creating `new` instances; their methods are NOT part of the public
 * API.
 *
 * That's to say that the objects should be passed to the verify() methods, but
 * don't try to interact with them beyond that.
 */
interface RelyingPartyInterface
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
