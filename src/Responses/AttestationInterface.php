<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Responses;

use Firehed\WebAuthn\{
    ChallengeInterface,
    CredentialInterface,
    RelyingParty,
    UserVerificationRequirement,
};

/**
 * The internal format associated with the response of
 * `navigator.credentials.create()`, to be verified in client code.
 *
 * @api
 */
interface AttestationInterface
{
    public function verify(
        ChallengeInterface $challenge,
        RelyingParty $rp,
        UserVerificationRequirement $uv = UserVerificationRequirement::Preferred,
    ): CredentialInterface;

    public function getChallenge(): ChallengeInterface;
}
