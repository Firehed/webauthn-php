<?php

declare(strict_types=1);

namespace Firehed\WebAuthn;

/**
 * In most cases, you will want to interact with ChallengeManagerInterface,
 * which extends this. That will let you generate challenges, manage (store)
 * them, and subsequently verify them if they're found in storage. This is
 * intended as the primary data flow, and is the recommended path.
 *
 * In rare circumstances, you may need to verify externally-managed challenges.
 * If so, the loading component may opt to only implement this interface. Doing
 * so is NOT RECOMMENDED at this time.
 *
 * @api (with the above caveats)
 */
interface ChallengeLoaderInterface
{
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
