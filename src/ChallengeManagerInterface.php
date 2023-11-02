<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

interface ChallengeManagerInterface
{
    /**
     * Generates a new Challenge, stores it in the backing mechanism, and
     * returns it.
     *
     * @api
     */
    public function createChallenge(): ChallengeInterface;

    /**
     * Consumes the challenge associated with the ClientDataJSON value from the
     * underlying storage mechanism, and returns that challenge if found.
     *
     * Implementations MUST ensure that subsequent calls to this method with
     * the same value return `null`, regardless of whether the initial call
     * returned a value or null. Failure to do so will compromise the security
     * of the webauthn protocol.
     *
     * Implementations MUST NOT use the ClientDataJSON value to construct
     * a challenge. They MUST return a previously-stored value if one is found,
     * and MAY use $base64Url to search the storage mechanism.
     *
     * @internal
     */
    public function useFromClientDataJSON(string $base64Url): ?ChallengeInterface;
}
