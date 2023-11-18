<?php

declare(strict_types=1);

namespace Firehed\WebAuthn\Responses;

use Firehed\WebAuthn\{
    ChallengeInterface,
    ChallengeManagerInterface,
    CredentialInterface,
    RelyingParty,
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
    public function isUserVerified(): bool;

    public function verify(
        ChallengeManagerInterface $challenge,
        RelyingParty $rp,
        UserVerificationRequirement $uv = UserVerificationRequirement::Preferred,
    ): CredentialInterface;
}
