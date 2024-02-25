<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Responses;

use Firehed\WebAuthn\{
    ChallengeInterface,
    ChallengeManagerInterface,
    CredentialInterface,
    RelyingPartyInterface,
    Enums\UserVerificationRequirement,
};

/**
 * The internal format associated with the response of
 * `navigator.credentials.create()`, to be verified in client code.
 *
 * @api
 */
interface AttestationInterface
{
    // isBackupEligible: bool (7.1.17)
    // isBackedUp: bool (7.1.18)
    //
    public function isUserVerified(): bool;

    public function verify(
        ChallengeManagerInterface $challenge,
        RelyingPartyInterface $rp,
        UserVerificationRequirement $uv = UserVerificationRequirement::Preferred,
        bool $rejectUncertainTrustPaths = true,
    ): CredentialInterface;
}
